// Copyright 2026 The logredact Authors
// SPDX-License-Identifier: MIT

// Package logredact masks a short, fixed list of well-known token formats,
// URL passwords, email addresses and home-directory paths in log text.
// Anything it does not recognise passes through unchanged, and no function
// returns an error.
//
// It has three entry points:
//
//   - [Redact] rewrites a free-form string: well-known token formats and the
//     password in a URL become "[REDACTED]", email addresses become
//     "u***@e***.com", and home directories such as "/Users/alice" become "~".
//   - [RedactStruct] applies the same rules to every string inside a
//     [structpb.Struct], in place, and masks by name every string under a field
//     called "email", "password", "api_key" and similar.
//   - [VendorErrorDetail] reduces a third-party API's error body to the short
//     strings without whitespace under a small allowlist of keys such as "code"
//     and "requestId", and drops everything else.
//
// All three functions are safe for concurrent use. RedactStruct mutates its
// argument.
//
// It is a defence-in-depth pass, not a guarantee. Redact and RedactStruct mask
// what they recognise and pass everything else through unchanged.
// VendorErrorDetail does the opposite and drops what it does not recognise.
package logredact

import (
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"google.golang.org/protobuf/types/known/structpb"
)

// piiKeys are field names whose string values are masked by maskPIIValue
// instead of by the Redact patterns. They are spelled as piiKeyName returns
// them, so "session_token", "sessionToken" and "Session-Token" all match
// "sessiontoken".
var piiKeys = map[string]struct{}{
	"email":              {},
	"name":               {},
	"token":              {},
	"secret":             {},
	"password":           {},
	"authorization":      {},
	"credentials":        {},
	"credential":         {},
	"creds":              {},
	"secrets":            {},
	"auth":               {},
	"session":            {},
	"sessiontoken":       {},
	"accesstoken":        {},
	"refreshtoken":       {},
	"apikey":             {},
	"xapikey":            {},
	"clientsecret":       {},
	"privatekey":         {},
	"cookie":             {},
	"passwd":             {},
	"pwd":                {},
	"apitoken":           {},
	"secretkey":          {},
	"accesskey":          {},
	"awssecretaccesskey": {},
	"setcookie":          {},
	"privatekeyid":       {},
	"dsn":                {},
	"connectionstring":   {},
	"otp":                {},
	"pin":                {},
}

// identityKeys are the PII keys whose values identify a person rather than
// hold a secret. Under these, a value that is one whole email address is masked
// as an address; every other PII-keyed value is cut to its first character.
// Each entry must also be in piiKeys.
var identityKeys = map[string]struct{}{
	"email": {},
	"name":  {},
}

var keySeparators = strings.NewReplacer("_", "", "-", "")

// piiKeyName is the spelling a field name is looked up by in piiKeys: lower
// case, with underscores and hyphens removed.
func piiKeyName(key string) string {
	return strings.ToLower(keySeparators.Replace(key))
}

// redactedPlaceholder is the replacement string written wherever a value is
// fully masked: a token-pattern match, a URL password, or an email match whose
// first domain label is empty.
const redactedPlaceholder = "[REDACTED]"

// tokenPatterns match well-known secret formats inside a string. Each match is
// replaced with tokenReplacement.
//
// Formats use documented prefixes; broad matches can also mask ordinary text. A prefix must follow tokenStart, so a prefix inside
// a word ("task-list" contains "sk-") is not a match. Bearer is the exception:
// it is matched anywhere, case-insensitively, because the word is what marks
// the credential.
//
// A pattern that starts with tokenStart has no literal prefix that Go's regexp
// can scan for, which makes it many times slower on text that does not contain
// the prefix. So each such pattern carries its literal prefix, and redactTokens
// skips the pattern when the text does not contain it. This cannot change the
// output, because prefixed builds every match to contain the prefix. An empty
// prefix means the pattern always runs.
var tokenPatterns = []tokenPattern{
	// PEM private keys span lines; public-key and certificate blocks are kept.
	prefixed("-----BEGIN ", `(?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----(?s:.*?)-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----`),

	// Bearer credential. A repeated scheme word ("Bearer Bearer x") is skipped so
	// that the credential after it is what gets matched. The gap after the word
	// is tabs or spaces of any script, never a line break.
	{"", regexp.MustCompile(`(?i)Bearer(?:[\t\v\f\p{Zs}]+Bearer)*[\t\v\f\p{Zs}]+\S+`)},
	// Google OAuth access token.
	prefixed("ya29.", `\S+`),
	// GitHub tokens: ghp_ (classic personal), gho_ (OAuth), ghs_ (server-to-server),
	// ghu_ (user-to-server), ghr_ (refresh).
	prefixed("gh", `[opsur]_\S+`),
	// GitHub fine-grained personal access token.
	prefixed("github_pat_", `\S+`),
	// "sk-" secret keys.
	prefixed("sk-", `\S+`),
	// Slack bot, user, legacy, refresh, session and rotation tokens.
	prefixed("xox", `[bpaers]-\S+`),
	// Slack app tokens and incoming webhooks.
	prefixed("xapp-", `\S+`),
	prefixed("https://hooks.slack.com/services/", `\S+`),
	// Google API keys have a fixed 39-character shape.
	prefixed("AIza", `[0-9A-Za-z_-]{35}`),
	// Stripe secret/restricted keys and webhook signing secrets.
	prefixed("sk_", `(?:live|test)_\S+`),
	prefixed("rk_", `(?:live|test)_\S+`),
	prefixed("whsec_", `\S+`),
	// GitLab, npm and SendGrid tokens.
	prefixed("glpat-", `\S+`),
	prefixed("npm_", `\S+`),
	prefixed("SG.", `[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`),
	// JSON Web Token: three base64url segments, the first two starting "eyJ". The
	// third, the signature, is empty in an unsecured token.
	prefixed("eyJ", `[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`),
	// AWS access key IDs: AKIA (long-term IAM user), ASIA (temporary STS
	// credential), ABIA (STS service bearer token) and ACCA (context-specific
	// credential). Unlike the other formats, the pattern matches the full ID's
	// fixed 20-character shape (the four-letter prefix plus 16 upper-case letters
	// or digits) rather than running to the next whitespace, because the prefix
	// alone can occur in ordinary upper-case text such as "ASIA-PACIFIC".
	prefixed("AKIA", `[0-9A-Z]{16}`),
	prefixed("ASIA", `[0-9A-Z]{16}`),
	prefixed("ABIA", `[0-9A-Z]{16}`),
	prefixed("ACCA", `[0-9A-Z]{16}`),
}

// tokenStart is what a token prefix must follow: the start of the text, any
// character other than an ASCII letter, or a percent-escape such as "%3D" or
// its double-encoded "%253D", so that "access_token%3Dya29.x" is a match. It
// is captured so that tokenReplacement can write it back.
const tokenStart = `(^|[^A-Za-z]|%(?:25)*[0-9A-Fa-f]{2})`

// tokenReplacement keeps the text matched by tokenStart. Bearer has no capture
// group, so ${1} is empty there.
const tokenReplacement = "${1}" + redactedPlaceholder

type tokenPattern struct {
	prefix string // literal every match contains; "" means no pre-check
	re     *regexp.Regexp
}

// prefixed builds a pattern that matches prefix, after tokenStart, followed by
// rest.
func prefixed(prefix, rest string) tokenPattern {
	return tokenPattern{prefix, regexp.MustCompile(tokenStart + regexp.QuoteMeta(prefix) + rest)}
}

// urlPasswordRegex matches the password in a URL's user information,
// "scheme://user:password@", with the user name optional. Like net/url, it
// takes the last "@" before the path as the end of the password, so a raw "@"
// inside the password is masked too.
var urlPasswordRegex = regexp.MustCompile(`(://[^\s/:@]*:)[^\s/?#]+@`)

var emailRegex = regexp.MustCompile(`[\p{L}\p{N}._%+\-]+@[\p{L}\p{N}.\-]+\.\p{L}{2,}`)

// homeDirRegex matches "/Users/<name>" and "/home/<name>" wherever they appear
// in a path. It does not know the current user's name, so it masks whatever
// path segment follows /Users or /home. The segment stops at a slash, at
// whitespace, and at the quotes, brackets and separators that end a path in
// log text.
var homeDirRegex = regexp.MustCompile(`/(?:Users|home)/[^/\s"'<>()\[\]{},;:|&?#=\\]+`)

// Redact returns s with all known token patterns, URL passwords, emails, and
// home directories replaced. Use it on free-form text such as log messages.
//
// The token patterns are: a Bearer credential (any case); tokens starting with
// ya29., gh[opsur]_, github_pat_, sk-, xox[bpaers]-, xapp-,
// sk_live_, sk_test_, rk_live_, rk_test_, whsec_, glpat-, npm_ or SG.;
// Slack incoming-webhook URLs; Google API keys (AIza plus 35 characters);
// PEM private-key blocks; a JWT (three base64url
// segments, the first two starting eyJ, the third possibly empty); and AWS
// access key IDs (AKIA, ASIA, ABIA or ACCA followed by 16 upper-case letters or
// digits). A prefix counts only at the start of the text, after a character
// other than an ASCII letter, or after a percent-escape. Each match becomes
// "[REDACTED]"; most run to the next whitespace, but an AWS access key ID
// matches only its fixed 20-character length, because the four-letter prefix
// alone can occur in ordinary upper-case text. The password in
// "scheme://user:password@" also becomes "[REDACTED]".
//
// Token patterns run first, then URL passwords, then emails, then home
// directories, so an email address that starts with a token prefix
// ("sk-alice@example.com") is redacted whole rather than masked as an address.
func Redact(s string) string {
	s = redactTokens(s)
	s = urlPasswordRegex.ReplaceAllString(s, "${1}"+redactedPlaceholder+"@")
	// Every address contains "@". The check skips the costliest pass on the
	// many lines that have none, and cannot change the output.
	if strings.Contains(s, "@") {
		s = emailRegex.ReplaceAllStringFunc(s, maskEmail)
	}
	s = homeDirRegex.ReplaceAllString(s, "~")
	return s
}

func redactTokens(s string) string {
	for _, p := range tokenPatterns {
		if p.prefix != "" && !strings.Contains(s, p.prefix) {
			continue
		}
		s = p.re.ReplaceAllString(s, tokenReplacement)
	}
	return s
}

// RedactStruct walks a structpb.Struct in place, at any depth. String leaves
// are passed through Redact, unless a PII key sits above them: email, name,
// token, secret, secrets, password, auth, authorization, credential,
// credentials, creds, session, session_token, access_token, refresh_token,
// api_key, x-api-key, client_secret, private_key, cookie, passwd, pwd, api_token,
// secret_key, access_key, aws_secret_access_key, set-cookie, private_key_id,
// dsn, connection_string, otp or pin.
// Keys are compared ignoring case, underscores and
// hyphens, so "apiKey" and "Api-Key" are api_key, but otherwise exactly, so
// "user_email" is not a PII key.
//
// A PII key applies to every string beneath it: its own value, the strings in
// a list under it, and the strings in a struct under it, unless a nearer key is
// itself a PII key. Under the identity keys, email and name, a value that is one
// whole email address is masked as an address. Every other PII-keyed value keeps
// only its first character followed by "***"; a value of one character or less
// is left as it is. A number under a secret key becomes the string mask of its
// decimal form, so 123456 becomes "1***"; a one-digit number is left as it is.
// Map keys, booleans, nulls and every other number are never changed. No-op on
// nil.
func RedactStruct(s *structpb.Struct) {
	redactFields(s.GetFields(), "")
}

// redactFields redacts every value in fields. piiKey is the nearest PII key
// above fields, or "" when there is none.
func redactFields(fields map[string]*structpb.Value, piiKey string) {
	for k, v := range fields {
		if isPIIKey(k) {
			redactValue(v, k)
		} else {
			redactValue(v, piiKey)
		}
	}
}

// redactValue redacts v in place. The protobuf getters are nil-safe, so a nil
// value, struct or list anywhere is skipped.
func redactValue(v *structpb.Value, piiKey string) {
	switch kind := v.GetKind().(type) {
	case *structpb.Value_StringValue:
		if piiKey != "" {
			kind.StringValue = maskPIIValue(piiKey, kind.StringValue)
		} else {
			kind.StringValue = Redact(kind.StringValue)
		}
	case *structpb.Value_NumberValue:
		// A PIN or a numeric password is a secret too. The value becomes the
		// string mask of its decimal form, because a number cannot hold "***".
		if piiKey != "" && !isIdentityKey(piiKey) {
			if n := strconv.FormatFloat(kind.NumberValue, 'f', -1, 64); len(n) > 1 {
				v.Kind = &structpb.Value_StringValue{StringValue: firstChar(n) + "***"}
			}
		}
	case *structpb.Value_StructValue:
		redactFields(kind.StructValue.GetFields(), piiKey)
	case *structpb.Value_ListValue:
		for _, item := range kind.ListValue.GetValues() {
			redactValue(item, piiKey)
		}
	}
}

func isPIIKey(key string) bool {
	_, ok := piiKeys[piiKeyName(key)]
	return ok
}

func isIdentityKey(key string) bool {
	_, ok := identityKeys[piiKeyName(key)]
	return ok
}

// maskPIIValue masks a value whose key is a PII key. Under an identity key, a
// value that is one whole email address is masked as an address. Anything else
// keeps only its first character, followed by ***.
func maskPIIValue(key, v string) string {
	if isIdentityKey(key) && isOneAddress(v) {
		return maskEmail(v)
	}
	if utf8.RuneCountInString(v) <= 1 {
		return v
	}
	return firstChar(v) + "***"
}

func isOneAddress(v string) bool {
	loc := emailRegex.FindStringIndex(v)
	return loc != nil && loc[0] == 0 && loc[1] == len(v)
}

// maskEmail masks one emailRegex match. The regex guarantees a non-empty local
// part, an @, and a domain that contains a dot, so the only case left to guard
// is an empty first domain label ("x@.example.com").
func maskEmail(email string) string {
	local, domain, _ := strings.Cut(email, "@")
	name, rest, _ := strings.Cut(domain, ".")
	if name == "" {
		return redactedPlaceholder
	}
	return firstChar(local) + "***@" + firstChar(name) + "***." + rest
}

// firstChar returns the first character of a non-empty s, or its first byte
// when s does not start with valid UTF-8.
func firstChar(s string) string {
	_, size := utf8.DecodeRuneInString(s)
	return s[:size]
}

// vendorDiagnosticKeys are response-body fields whose values are short
// strings without whitespace rather than prose: safe to carry into an error or
// a log line. The list is deliberately short. Anything absent from it,
// including a vendor's human-readable message, is dropped, because a validation
// message routinely quotes the value that failed validation, and that value is
// the caller's own submitted payload. They are listed in byte order, which is
// the order of the output.
var vendorDiagnosticKeys = []string{
	"category",
	"code",
	"correlationId",
	"correlation_id",
	"errorType",
	"error_code",
	"requestId",
	"status",
}

// maxVendorDiagnosticValue bounds an admitted value. An identifier is short and
// has no spaces; anything longer or containing whitespace is prose wearing an
// allowlisted key, and is dropped.
const maxVendorDiagnosticValue = 64

// VendorErrorDetail summarises an external API's error body for an error
// message or a log line. It keeps only short strings without whitespace under
// an allowlisted key and drops everything else.
//
// The allowlisted keys are category, code, correlationId, correlation_id,
// errorType, error_code, requestId and status, matched case-insensitively as
// quoted JSON keys at any depth. For each key, the first occurrence whose value
// is a quoted string without quotes or backslashes is taken, and it is kept
// only if it is 1 to 64 bytes of valid UTF-8 with no whitespace, control or
// other invisible character; otherwise the key is dropped. Each kept value is passed
// through Redact, and the results are returned as key=value pairs, sorted by
// key and separated by spaces. The body is scanned, never parsed, so a
// malformed body cannot fail and is never passed through. It returns "" when
// nothing is admitted. Pair it with the HTTP status, which is always safe.
func VendorErrorDetail(body []byte) string {
	s := string(body)
	var kept []string
	for _, p := range vendorDiagnosticPatterns {
		m := p.re.FindStringSubmatch(s)
		// Re-validated after matching, not trusted because the key was allowlisted.
		if m == nil || !isDiagnosticValue(m[1]) {
			continue
		}
		kept = append(kept, p.key+"="+Redact(m[1]))
	}
	return strings.Join(kept, " ")
}

// isDiagnosticValue reports whether v is 1 to maxVendorDiagnosticValue bytes of
// valid UTF-8 made only of visible characters other than spaces.
func isDiagnosticValue(v string) bool {
	return v != "" && len(v) <= maxVendorDiagnosticValue && utf8.ValidString(v) &&
		strings.IndexFunc(v, isBlankOrInvisible) < 0
}

// isBlankOrInvisible reports whether r is whitespace, a control or format
// character, or a character that renders as nothing, such as the Hangul filler
// U+3164 or the braille blank U+2800, which can stand in for a space.
func isBlankOrInvisible(r rune) bool {
	return unicode.IsSpace(r) || !unicode.IsGraphic(r) ||
		unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r) || r == '⠀'
}

type vendorDiagnosticPattern struct {
	key string
	re  *regexp.Regexp
}

// vendorDiagnosticPatterns holds one compiled pattern per allowlisted key, in
// the order of vendorDiagnosticKeys.
var vendorDiagnosticPatterns = compileVendorDiagnosticPatterns()

func compileVendorDiagnosticPatterns() []vendorDiagnosticPattern {
	patterns := make([]vendorDiagnosticPattern, 0, len(vendorDiagnosticKeys))
	for _, k := range vendorDiagnosticKeys {
		patterns = append(patterns, vendorDiagnosticPattern{key: k, re: vendorDiagnosticRegexp(k)})
	}
	return patterns
}

// vendorDiagnosticRegexp matches one allowlisted key's string value.
// Case-insensitive on the key because vendors differ in casing (requestId,
// RequestID); spelling variants such as correlationId and correlation_id are
// separate allowlist entries. The value class is deliberately narrow: no
// escapes, no quotes, so a value containing either simply does not match and is
// dropped rather than half-read.
func vendorDiagnosticRegexp(key string) *regexp.Regexp {
	return regexp.MustCompile(`(?i)"` + regexp.QuoteMeta(key) + `"\s*:\s*"([^"\\]*)"`)
}

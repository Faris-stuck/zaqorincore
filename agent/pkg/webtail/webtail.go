// Package webtail parses web server log lines (nginx access log
// in "combined" format, ModSecurity audit log in native format)
// into structured fields suitable for ZaqorinCore event.Metadata.
//
// This package is intentionally parser-only: it does not know
// about transport, channels, or the wire schema. Callers feed
// raw bytes in via ParseNginxLine / ParseModSecLine and get a
// map[string]string out (or an error explaining why the line
// could not be parsed).
//
// Why a map and not a struct? Because ZaqorinCore's on-wire
// Event.Metadata is already map[string]string. We want to
// drop the parsed result straight in without an intermediate
// struct-to-map conversion at the hot path. The trade-off is
// no compile-time field name safety — see the constants
// below for the canonical key names that match the Sigma
// rule library under server/rules/builtin/*.
package webtail

import (
	"fmt"
	"strconv"
	"strings"
)

// Metadata key names. These MUST match the field names referenced
// by Sigma rules under server/rules/builtin/* — if you rename one,
// also update the rules.
const (
	KeySourceIP   = "src_ip"
	KeyMethod     = "http_method"
	KeyURI        = "uri"
	KeyStatus     = "status_code"
	KeyBytes      = "bytes_sent"
	KeyReferer    = "referer"
	KeyUserAgent  = "user_agent"
	KeyRequestID  = "request_id"
	KeyAuthUser   = "auth_user"
	KeyRuleIDs    = "modsec_rule_ids"
	KeyRuleMsg    = "modsec_rule_message"
	KeySeverity   = "modsec_severity"
	KeyMatchedVar = "modsec_matched_var"
)

// NginxAccessFormat is the canonical "combined" log format that
// nginx ships with by default (http_combined in the ngx_http_log_module
// docs). It is:
//
//	$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
//
// We do NOT attempt to handle every conceivable custom log_format
// directive — we recognise the combined format by structure
// (5 quoted-or-dash fields after the bracketed timestamp) and
// reject anything else. Operators who run a custom format can
// either reconfigure nginx to "combined" or extend this parser
// with a new branch.

// ParseNginxLine parses one nginx access log line (combined
// format). Returns the field map and a bool indicating whether
// the line was recognised. Lines that are not parseable are
// returned with ok=false and err=nil — callers typically choose
// to drop them silently because tailers also feed in legitimate
// noise lines (heartbeats, blank lines from logrotate).
//
// Example input:
//
//	203.0.113.42 - alice [30/Aug/2026:12:34:56 +0000] "GET /admin/users?id=1 HTTP/1.1" 200 1234 "https://example.com/" "Mozilla/5.0"
//
// Example output map:
//
//	{
//	  "src_ip": "203.0.113.42",
//	  "auth_user": "alice",
//	  "http_method": "GET",
//	  "uri": "/admin/users?id=1",
//	  "status_code": "200",
//	  "bytes_sent": "1234",
//	  "referer": "https://example.com/",
//	  "user_agent": "Mozilla/5.0",
//	}
//
// Performance: ~1 allocation per parse (the returned map). For
// high-throughput web servers, the agent should pool these maps
// via sync.Pool at a higher layer; this package keeps the parser
// itself allocation-cheap and easy to test.
func ParseNginxLine(raw string) (map[string]string, bool, error) {
	// Cheap pre-check: combined format always starts with an
	// IPv4 (or "-" for missing) and has a "[" bracketed timestamp
	// before the request. Anything else we ignore.
	if len(raw) == 0 {
		return nil, false, nil
	}
	// Strip trailing newline if present.
	raw = strings.TrimRight(raw, "\r\n")
	if raw == "" {
		return nil, false, nil
	}

	// Field 1: remote_addr (up to first space)
	sp1 := strings.IndexByte(raw, ' ')
	if sp1 < 0 {
		return nil, false, nil
	}
	srcIP := raw[:sp1]
	rest := raw[sp1+1:]

	// Field 2: remote_user (literal "-" if anonymous, else up to space).
	// Note: nginx combined format is "$remote_addr - $remote_user [time] ..."
	// so between remote_addr and remote_user there are TWO spaces (with
	// a literal "-" in between). We skip the "-" by IndexByte for " - ".
	// Simpler approach: scan forward to the bracketed timestamp directly
	// and remember the byte just before it as the remote_user.
	// We split the head into tokens: rest[0:sp_at_dash] is "-",
	// rest[sp_at_dash:bracket_at] is remote_user.
	var remoteUser string
	dashIdx := strings.IndexByte(rest, '-')
	if dashIdx < 0 {
		return nil, false, nil
	}
	rest = rest[dashIdx+1:]
	// Skip the literal "-" that nginx emits when remote_user is empty.
	// After dash we may have either " - " (anonymous) or " alice" (named user).
	// Trim leading whitespace, then take everything up to the next space
	// (which delimits the remote_user from the bracketed timestamp).
	rest = strings.TrimLeft(rest, " ")
	sp2 := strings.IndexByte(rest, ' ')
	if sp2 < 0 {
		return nil, false, nil
	}
	remoteUser = rest[:sp2]
	rest = rest[sp2+1:]
	if rest == "" || rest[0] != '[' {
		return nil, false, nil
	}
	tEnd := strings.IndexByte(rest, ']')
	if tEnd < 0 {
		return nil, false, nil
	}
	// We don't parse the timestamp — the agent stamps its own
	// wall-clock at construction time, which is the source of
	// truth on the server side. Skip to after "] ".
	rest = strings.TrimPrefix(rest[tEnd+1:], " ")
	if rest == "" || rest[0] != '"' {
		return nil, false, nil
	}

	// Field 4: "REQUEST" (quoted, may contain spaces — split on
	// the closing quote, not on space).
	reqEnd := strings.IndexByte(rest[1:], '"')
	if reqEnd < 0 {
		return nil, false, nil
	}
	request := rest[1 : 1+reqEnd]
	rest = rest[1+reqEnd+2:] // skip closing quote + space
	if rest == "" {
		return nil, false, nil
	}

	// Split request into METHOD URI PROTOCOL (3 tokens; we keep
	// method and uri, drop protocol — Sigma rules don't need it
	// and we save a string copy).
	parts := strings.SplitN(request, " ", 3)
	if len(parts) < 3 {
		return nil, false, nil
	}
	method, uri := parts[0], parts[1]

	// Field 5: status code (numeric)
	sp5 := strings.IndexByte(rest, ' ')
	if sp5 < 0 {
		return nil, false, nil
	}
	statusStr := rest[:sp5]
	if _, err := strconv.Atoi(statusStr); err != nil {
		return nil, false, nil
	}
	rest = rest[sp5+1:]

	// Field 6: body_bytes_sent (numeric)
	sp6 := strings.IndexByte(rest, ' ')
	if sp6 < 0 {
		return nil, false, nil
	}
	bytesStr := rest[:sp6]
	if _, err := strconv.Atoi(bytesStr); err != nil {
		return nil, false, nil
	}
	rest = rest[sp6+1:]

	// Field 7: "referer" (quoted, may be "-")
	referer := extractQuoted(&rest)
	if referer == "-" {
		referer = ""
	}

	// Field 8: "user_agent" (quoted, may be "-"). Whatever's
	// left in the line is the UA (mod_security audit log
	// sometimes appends extra fields, so we don't require the
	// quote to be balanced).
	ua := extractQuoted(&rest)
	if ua == "-" {
		ua = ""
	}

	out := make(map[string]string, 8)
	if srcIP != "-" {
		out[KeySourceIP] = srcIP
	}
	if remoteUser != "-" {
		out[KeyAuthUser] = remoteUser
	}
	out[KeyMethod] = method
	out[KeyURI] = uri
	out[KeyStatus] = statusStr
	out[KeyBytes] = bytesStr
	if referer != "" {
		out[KeyReferer] = referer
	}
	if ua != "" {
		out[KeyUserAgent] = ua
	}
	return out, true, nil
}

// extractQuoted reads a `"..."` token from the head of s, advances
// s past the closing quote + following space, and returns the
// unquoted contents. If the head is not a quote, returns "" and
// leaves s unchanged. Handles the "-" sentinel used by nginx for
// "no value".
func extractQuoted(s *string) string {
	if len(*s) == 0 || (*s)[0] != '"' {
		return ""
	}
	// Find closing quote.
	for i := 1; i < len(*s); i++ {
		if (*s)[i] == '"' {
			val := (*s)[1:i]
			*s = strings.TrimPrefix((*s)[i+1:], " ")
			return val
		}
	}
	return ""
}

// ParseModSecLine parses a single ModSecurity "audit log" line.
// ModSecurity's audit log is multi-line and section-based, so
// callers typically feed each line through this function and
// accumulate the per-request state themselves. This function
// returns:
//
//   - section: one of "A", "B", "C", "E", "F", "H", "I", "J", "K", "Z"
//   - fields:  map of key=value pairs found on this line
//   - endTxn:  true if this line ends a transaction (audit log
//     section "Z") — callers should flush their accumulated state.
//
// Recognised lines:
//
//	--section-- (e.g. "--A--", "--B--", "--Z--")
//	KEY VALUE    (within a section)
//	--section-end-- (e.g. "--A--")
//
// Lines that don't match either form return (section="", ok=false)
// and are silently ignored.
//
// Resource bounds: The tailer (nxadm/tail → bufio.Scanner) enforces a
// 64KB default line cap upstream. This parser is O(n) on line length
// using IndexByte and SplitN (no quadratic blowup) and adds its own
// 1MB safety cap so a misconfigured tailer or future in-process caller
// cannot exhaust memory with a pathological 1GB line. Lines above the
// cap return ok=false silently — same as malformed input.
const modSecMaxLineBytes = 1 << 20 // 1 MiB

// Lines that don't match either form return (section="", ok=false)
// and are silently ignored.
//
// Example audit log excerpt:
//
//	--5d7c1e2a-A--
//	[30/Aug/2026:12:34:56.123456 +0000] Vh3BkQe2C5d7c1e2a 203.0.113.42 12345 10.0.0.5 80
//	--5d7c1e2a-B--
//	GET /admin/users?id=1 HTTP/1.1
//	Host: example.com
//	User-Agent: Mozilla/5.0
//	...
//	--5d7c1e2a-F--
//	HTTP/1.1 200 OK
//	...
//	--5d7c1e2a-Z--
func ParseModSecLine(line string) (section string, fields map[string]string, endTxn bool, ok bool) {
	// Defense-in-depth line cap. The tailer (bufio.Scanner) already
	// caps at 64KB by default; this guard protects against future
	// in-process callers or a tailer misconfiguration.
	if len(line) > modSecMaxLineBytes {
		return "", nil, false, false
	}
	line = strings.TrimRight(line, "\r\n")
	if len(line) == 0 {
		return "", nil, false, false
	}

	// Section marker: "--HEXID-SECTION--" or "--HEXID-SECTION-end--"
	if strings.HasPrefix(line, "--") && strings.HasSuffix(line, "--") {
		body := strings.TrimPrefix(strings.TrimSuffix(line, "--"), "--")
		// body = "HEXID-SECTION" or "HEXID-SECTION-end"
		dash := strings.LastIndex(body, "-")
		if dash < 0 {
			return "", nil, false, false
		}
		sectionCode := body[dash+1:]
		if sectionCode == "end" {
			// "--HEXID-SECTION-end--" — end of section
			// We don't know which section closed; callers
			// match on the previously-opened id.
			return "", nil, false, true
		}
		// Section opening — sectionCode is single letter
		// (A, B, C, E, F, H, I, J, K, Z). Validate.
		if len(sectionCode) != 1 {
			return "", nil, false, false
		}
		c := sectionCode[0]
		switch c {
		case 'A', 'B', 'C', 'E', 'F', 'H', 'I', 'J', 'K', 'Z':
			return sectionCode, nil, c == 'Z', true
		default:
			return "", nil, false, false
		}
	}

	// Within a section, lines are "KEY VALUE" or just a value.
	// The most useful fields for Sigma rules are in section B
	// (request headers) and section H (audit log trailer, which
	// lists triggered rules). We extract:
	//   Host: ...            -> "host"
	//   User-Agent: ...      -> "user_agent"
	//   Referer: ...         -> "referer"
	//   Cookie: ...          -> "cookie"
	//   --everything else--  -> pass-through as "msg"
	//
	// ModSecurity audit log lines are case-sensitive in the
	// section markers but case-insensitive in HTTP header
	// names. We match HTTP headers in their canonical case
	// (Title-Case-Hyphenated).
	colon := strings.IndexByte(line, ':')
	if colon < 0 {
		// No colon — treat as opaque message
		return "", map[string]string{"msg": line}, false, true
	}
	key := strings.TrimSpace(line[:colon])
	val := strings.TrimSpace(line[colon+1:])

	fields = map[string]string{
		strings.ToLower(strings.ReplaceAll(key, "-", "_")): val,
	}
	return "", fields, false, true
}

// FormatNginxExample returns a one-line example of the nginx
// combined format. Useful for docs and golden tests.
func FormatNginxExample() string {
	return `203.0.113.42 - alice [30/Aug/2026:12:34:56 +0000] ` +
		`"GET /admin/users?id=1 HTTP/1.1" 200 1234 ` +
		`"https://example.com/" "Mozilla/5.0"`
}

// ValidateURI is a small helper used by some Sigma rules that
// need a quick "does this URI look like an attack?" check
// without firing the full rule engine. Returns nil if the URI
// looks plausible; returns an error string (NOT a typed error)
// describing the first suspicious pattern matched.
//
// This is intentionally conservative — false positives here are
// more expensive than false negatives because they feed into
// the rule engine and can dispatch a block_ip action.
//
// Patterns cover BOTH raw and URL-encoded forms. URI query
// strings encode spaces as "+" and "<" as "%3c" — the
// Sigma rule engine runs on the raw URI before any decode,
// so we must match the encoded form too.
func ValidateURI(uri string) error {
	low := strings.ToLower(uri)
	switch {
	case strings.Contains(low, "union%20select"),
		strings.Contains(low, "union select"),
		strings.Contains(low, "union+select"),
		strings.Contains(low, "or 1=1"),
		strings.Contains(low, "or+1=1"),
		strings.Contains(low, "or 1="),
		strings.Contains(low, "or+1="),
		strings.Contains(low, "or%201="),
		strings.Contains(low, "%27%20or%20"),
		strings.Contains(low, "or%20%27"),
		strings.Contains(low, "' or '"),
		strings.Contains(low, "'+or+'"):
		return fmt.Errorf("uri contains SQLi marker (UNION SELECT / OR 1=1)")
	case strings.Contains(low, "<script"),
		strings.Contains(low, "%3cscript"),
		strings.Contains(low, "+script+"),
		strings.Contains(low, "javascript:"),
		strings.Contains(low, "onerror="),
		strings.Contains(low, "onerror%3d"):
		return fmt.Errorf("uri contains XSS marker")
	case strings.Contains(low, "../"),
		strings.Contains(low, "..%2f"),
		strings.Contains(low, "..\\"),
		strings.Contains(low, "%2e%2e"),
		strings.Contains(low, "..%252f"):
		return fmt.Errorf("uri contains path-traversal marker")
	}
	return nil
}
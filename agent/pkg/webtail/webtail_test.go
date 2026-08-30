// Tests for pkg/webtail. All offline — no live web server, no
// network, no eBPF. Tests parse fixtures written into testdata/.
package webtail

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestParseNginxLine_Canonical verifies the parser against a
// textbook "combined" format line.
func TestParseNginxLine_Canonical(t *testing.T) {
	raw := `203.0.113.42 - alice [30/Aug/2026:12:34:56 +0000] ` +
		`"GET /admin/users?id=1 HTTP/1.1" 200 1234 ` +
		`"https://example.com/" "Mozilla/5.0 (X11; Linux x86_64)"`

	got, ok, err := ParseNginxLine(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatalf("expected ok=true, got false")
	}
	want := map[string]string{
		KeySourceIP:  "203.0.113.42",
		KeyAuthUser:  "alice",
		KeyMethod:    "GET",
		KeyURI:       "/admin/users?id=1",
		KeyStatus:    "200",
		KeyBytes:     "1234",
		KeyReferer:   "https://example.com/",
		KeyUserAgent: "Mozilla/5.0 (X11; Linux x86_64)",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("key %q: got %q, want %q", k, got[k], v)
		}
	}
}

// TestParseNginxLine_Anonymous verifies that the literal "-"
// sentinels for missing user/referer are dropped (we don't want
// to grep for src_ip="-" later).
func TestParseNginxLine_Anonymous(t *testing.T) {
	raw := `198.51.100.7 - - [30/Aug/2026:12:34:57 +0000] ` +
		`"POST /api/login HTTP/1.1" 401 42 "-" "curl/7.81.0"`
	got, ok, err := ParseNginxLine(raw)
	if err != nil || !ok {
		t.Fatalf("parse failed: ok=%v err=%v", ok, err)
	}
	if _, exists := got[KeyAuthUser]; exists {
		t.Errorf("expected no auth_user for anonymous request, got %q", got[KeyAuthUser])
	}
	if _, exists := got[KeyReferer]; exists {
		t.Errorf("expected no referer for \"-\", got %q", got[KeyReferer])
	}
	if got[KeyMethod] != "POST" {
		t.Errorf("method: got %q, want POST", got[KeyMethod])
	}
	if got[KeyStatus] != "401" {
		t.Errorf("status: got %q, want 401", got[KeyStatus])
	}
}

// TestParseNginxLine_TrailingNewline ensures the parser tolerates
// the trailing \n that nxadm/tail includes.
func TestParseNginxLine_TrailingNewline(t *testing.T) {
	raw := `10.0.0.5 - - [01/Jan/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 0 "-" "curl/8.0"` + "\n"
	got, ok, err := ParseNginxLine(raw)
	if err != nil || !ok {
		t.Fatalf("parse failed: ok=%v err=%v", ok, err)
	}
	if got[KeySourceIP] != "10.0.0.5" {
		t.Errorf("src_ip: got %q", got[KeySourceIP])
	}
}

// TestParseNginxLine_RejectsMalformed verifies that lines that
// don't match the combined format are silently ignored (ok=false,
// err=nil).
func TestParseNginxLine_RejectsMalformed(t *testing.T) {
	cases := []string{
		"",
		"\n",
		"hello world",
		`203.0.113.42 - alice not-a-timestamp`,
		`203.0.113.42 - alice [30/Aug/2026:12:34:56 +0000] missingquotes`,
	}
	for _, c := range cases {
		_, ok, err := ParseNginxLine(c)
		if err != nil {
			t.Errorf("input %q: unexpected err=%v", c, err)
		}
		if ok {
			t.Errorf("input %q: expected ok=false, got true", c)
		}
	}
}

// TestParseNginxLine_URIQueryString verifies query strings are
// preserved (don't URL-decode; let Sigma rules match on patterns).
func TestParseNginxLine_URIQueryString(t *testing.T) {
	raw := `203.0.113.42 - - [30/Aug/2026:12:00:00 +0000] ` +
		`"GET /search?q=foo%27%20OR%20%271%27%3D%271 HTTP/1.1" 200 100 "-" "Mozilla"`
	got, ok, _ := ParseNginxLine(raw)
	if !ok {
		t.Fatal("parse failed")
	}
	if !strings.Contains(got[KeyURI], "OR") {
		t.Errorf("URI query lost characters: %q", got[KeyURI])
	}
}

// TestParseNginxLine_FromFixtures exercises the parser against
// real-ish log lines saved under testdata/. This is the regression
// net — if someone changes nginx's default format, we'll catch it.
func TestParseNginxLine_FromFixtures(t *testing.T) {
	path := filepath.Join("testdata", "nginx_access.log")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("fixture missing: %v", err)
	}
	lines := strings.Split(string(data), "\n")
	parsed := 0
	for _, ln := range lines {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		got, ok, err := ParseNginxLine(ln)
		if err != nil {
			t.Errorf("line %q: parse error %v", ln, err)
			continue
		}
		if !ok {
			t.Errorf("line %q: not recognised", ln)
			continue
		}
		if got[KeySourceIP] == "" {
			t.Errorf("line %q: missing src_ip", ln)
		}
		parsed++
	}
	if parsed < 5 {
		t.Errorf("only parsed %d lines from fixture; expected at least 5", parsed)
	}
}

// TestParseModSecLine_SectionMarkers verifies section open/close
// detection.
func TestParseModSecLine_SectionMarkers(t *testing.T) {
	cases := []struct {
		line     string
		wantSec  string
		wantEnd  bool
		wantOK   bool
	}{
		{"--5d7c1e2a-A--", "A", false, true},
		{"--5d7c1e2a-B--", "B", false, true},
		{"--5d7c1e2a-Z--", "Z", true, true},
		{"--5d7c1e2a-B-end--", "", false, true},
		{"--not-a-section--", "", false, false},
		{"--5d7c1e2a-X--", "", false, false}, // X is not a valid section
	}
	for _, c := range cases {
		sec, _, end, ok := ParseModSecLine(c.line)
		if sec != c.wantSec || end != c.wantEnd || ok != c.wantOK {
			t.Errorf("line %q: got (sec=%q end=%v ok=%v), want (sec=%q end=%v ok=%v)",
				c.line, sec, end, ok, c.wantSec, c.wantEnd, c.wantOK)
		}
	}
}

// TestParseModSecLine_RequestLine verifies that the request line
// in section B comes back as a useful message.
func TestParseModSecLine_RequestLine(t *testing.T) {
	_, fields, _, ok := ParseModSecLine("GET /admin/users?id=1 HTTP/1.1")
	if !ok {
		t.Fatal("parse failed")
	}
	if fields["msg"] != "GET /admin/users?id=1 HTTP/1.1" {
		t.Errorf("got %q", fields["msg"])
	}
}

// TestParseModSecLine_Header verifies that a Host: header comes
// back as "host".
func TestParseModSecLine_Header(t *testing.T) {
	_, fields, _, ok := ParseModSecLine("Host: example.com")
	if !ok {
		t.Fatal("parse failed")
	}
	if fields["host"] != "example.com" {
		t.Errorf("got %q", fields["host"])
	}
}

// TestParseModSecLine_FromFixtures is the regression test for
// the audit log fixture.
func TestParseModSecLine_FromFixtures(t *testing.T) {
	path := filepath.Join("testdata", "modsec_audit.log")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("fixture missing: %v", err)
	}
	sawSection := false
	sawRule := false
	for _, ln := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		sec, fields, _, ok := ParseModSecLine(ln)
		if !ok {
			continue
		}
		if sec == "B" {
			sawSection = true
		}
		if fields != nil && strings.Contains(fields["msg"], "SQL Injection") {
			sawRule = true
		}
	}
	if !sawSection {
		t.Error("fixture did not contain a section-B marker")
	}
	if !sawRule {
		t.Error("fixture did not contain a SQL Injection rule message")
	}
}

// TestValidateURI covers the quick attack-pattern check used by
// some rules to short-circuit the full rule engine.
func TestValidateURI(t *testing.T) {
	cases := []struct {
		uri       string
		wantErr   bool
		markerSub string
	}{
		{"/index.html", false, ""},
		{"/admin/users?id=1", false, ""},
		{"/search?q=foo'+OR+1=1", true, "SQLi"},
		{"/search?q=foo%27%20OR%20%271%27%3D%271", true, "SQLi"},
		{"/page?x=<script>alert(1)</script>", true, "XSS"},
		{"/page?x=%3cscript%3ealert(1)%3c/script%3e", true, "XSS"},
		{"/../../../etc/passwd", true, "path-traversal"},
		{"/static/..%2f..%2fetc/passwd", true, "path-traversal"},
	}
	for _, c := range cases {
		err := ValidateURI(c.uri)
		if c.wantErr && err == nil {
			t.Errorf("uri %q: expected error, got nil", c.uri)
		}
		if !c.wantErr && err != nil {
			t.Errorf("uri %q: unexpected error %v", c.uri, err)
		}
		if c.wantErr && err != nil && !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(c.markerSub)) {
			t.Errorf("uri %q: error %q did not mention %q", c.uri, err, c.markerSub)
		}
	}
}

// TestFormatNginxExample is a smoke test for the docs helper.
func TestFormatNginxExample(t *testing.T) {
	ex := FormatNginxExample()
	got, ok, err := ParseNginxLine(ex)
	if err != nil || !ok {
		t.Fatalf("example not parseable: ok=%v err=%v", ok, err)
	}
	if got[KeyMethod] != "GET" {
		t.Errorf("example method: got %q", got[KeyMethod])
	}
}
package command

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

var ErrFailed = errors.New("operation failed; credentials and remote details withheld")
var ErrInput = errors.New("invalid command input")

type response struct {
	status int
	header http.Header
	body   map[string]any
}
type api struct {
	origin, kind, credential string
	client                   *http.Client
}

func origin(raw string) (string, error) {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || (u.Path != "" && u.Path != "/") {
		return "", ErrInput
	}
	u.Scheme = "https"
	u.Host = strings.ToLower(u.Host)
	if u.Port() == "443" {
		u.Host = strings.TrimSuffix(u.Host, ":443")
	}
	u.Path = ""
	return u.String(), nil
}
func client(transport http.RoundTripper) *http.Client {
	return &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
func nonce() (string, error) {
	b := make([]byte, 24)
	if _, e := rand.Read(b); e != nil {
		return "", ErrFailed
	}
	return hex.EncodeToString(b), nil
}
func (a *api) call(ctx context.Context, method, path string, body any, idempotent bool) (response, error) {
	var data []byte
	var e error
	if body != nil {
		data, e = json.Marshal(body)
		if e != nil {
			return response{}, ErrInput
		}
	}
	r, e := http.NewRequestWithContext(ctx, method, a.origin+path, bytes.NewReader(data))
	if e != nil {
		return response{}, ErrInput
	}
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	r.Header.Set("Accept", "application/json")
	if idempotent {
		k, e := nonce()
		if e != nil {
			return response{}, e
		}
		r.Header.Set("Idempotency-Key", k)
	}
	switch a.kind {
	case "session":
		if a.credential != "" {
			r.AddCookie(&http.Cookie{Name: "provenance_session", Value: a.credential})
		}
	case "project-token":
		if a.credential != "" {
			r.Header.Set("Authorization", "Bearer "+a.credential)
		}
	}
	res, e := a.client.Do(r)
	if e != nil {
		return response{}, ErrFailed
	}
	defer res.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(res.Body, 4*1024*1024+1))
	if e != nil || len(raw) > 4*1024*1024 {
		return response{}, ErrFailed
	}
	kind, _, e := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if e != nil || (kind != "application/json" && kind != "application/problem+json") {
		return response{}, ErrFailed
	}
	value, e := object(raw)
	if e != nil {
		return response{}, e
	}
	return response{res.StatusCode, res.Header.Clone(), value}, nil
}
func object(raw []byte) (map[string]any, error) {
	if !utf8.Valid(raw) {
		return nil, ErrFailed
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	v, e := readJSON(d, 0)
	if e != nil {
		return nil, ErrFailed
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, ErrFailed
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, ErrFailed
	}
	return m, nil
}
func readJSON(d *json.Decoder, depth int) (any, error) {
	if depth > 64 {
		return nil, ErrFailed
	}
	v, e := d.Token()
	if e != nil {
		return nil, ErrFailed
	}
	switch x := v.(type) {
	case json.Delim:
		if x == '{' {
			m := map[string]any{}
			for d.More() {
				k, e := d.Token()
				s, ok := k.(string)
				if e != nil || !ok {
					return nil, ErrFailed
				}
				if _, ok = m[s]; ok {
					return nil, ErrFailed
				}
				m[s], e = readJSON(d, depth+1)
				if e != nil {
					return nil, e
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim('}') {
				return nil, ErrFailed
			}
			return m, nil
		}
		if x == '[' {
			a := []any{}
			for d.More() {
				v, e := readJSON(d, depth+1)
				if e != nil {
					return nil, e
				}
				a = append(a, v)
			}
			end, e := d.Token()
			if e != nil || end != json.Delim(']') {
				return nil, ErrFailed
			}
			return a, nil
		}
		return nil, ErrFailed
	default:
		return v, nil
	}
}
func text(m map[string]any, k string) string { v, _ := m[k].(string); return v }
func integer(m map[string]any, k string) int64 {
	n, ok := m[k].(json.Number)
	if !ok {
		return -1
	}
	i, e := n.Int64()
	if e != nil {
		return -1
	}
	return i
}
func deadline(m map[string]any) (time.Time, error) {
	t, e := time.Parse(time.RFC3339Nano, text(m, "expiresAt"))
	if e != nil {
		return t, ErrFailed
	}
	return t, nil
}
func wait(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ErrFailed
	case <-t.C:
		return nil
	}
}
func retryAfter(h http.Header) (time.Duration, error) {
	n, e := strconv.ParseInt(h.Get("Retry-After"), 10, 64)
	if e != nil || n < 1 || n > 86400 {
		return 0, ErrFailed
	}
	return time.Duration(n) * time.Second, nil
}

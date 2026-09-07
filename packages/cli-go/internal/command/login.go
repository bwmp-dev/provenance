package command

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var secretRE = regexp.MustCompile(`^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$`)
var userCodeRE = regexp.MustCompile(`^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$`)

func (a App) login(ctx context.Context, api *api) error {
	if a.Store.Ready(ctx) != nil {
		return ErrFailed
	}
	initial, e := api.call(ctx, "POST", "/v1/auth/device-authorizations", map[string]string{"clientName": "Provenance CLI"}, true)
	if e != nil || initial.status != 201 || initial.header.Get("Cache-Control") != "no-store" {
		return ErrFailed
	}
	device, code, uri := text(initial.body, "deviceCode"), text(initial.body, "userCode"), text(initial.body, "verificationUri")
	interval := integer(initial.body, "intervalSeconds")
	expires, e := deadline(initial.body)
	u, ue := url.Parse(uri)
	if e != nil || ue != nil || len(initial.body) != 5 || !secretRE.MatchString(device) || !userCodeRE.MatchString(code) || len(uri) > 2048 || strings.Contains(uri, device) || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || interval < 1 || interval > 86400 || !expires.After(time.Now()) {
		return ErrFailed
	}
	fmt.Fprintf(a.Out, "Open %s and enter %s\n", uri, code)
	loginCtx, cancel := context.WithDeadline(ctx, expires)
	defer cancel()
	delay := time.Duration(interval) * time.Second
	for {
		if wait(loginCtx, delay) != nil {
			return ErrFailed
		}
		r, e := api.call(loginCtx, "POST", "/v1/auth/device-authorizations/exchanges", map[string]string{"deviceCode": device}, false)
		if e != nil || r.header.Get("Cache-Control") != "no-store" {
			return ErrFailed
		}
		switch r.status {
		case 429:
			delay, e = retryAfter(r.header)
			if e != nil {
				return e
			}
			continue
		case 202:
			next, err := deadline(r.body)
			n := integer(r.body, "intervalSeconds")
			if err != nil || len(r.body) != 3 || text(r.body, "state") != "pending" || n < 1 || n > 86400 || next.After(expires) {
				return ErrFailed
			}
			delay = time.Duration(n) * time.Second
			if retry := r.header.Get("Retry-After"); retry != "" {
				d, e := retryAfter(r.header)
				if e != nil {
					return e
				}
				if d > delay {
					delay = d
				}
			}
			if next.Before(expires) {
				cancel()
				expires = next
				loginCtx, cancel = context.WithDeadline(ctx, expires)
				defer cancel()
			}
			continue
		case 200:
			token := text(r.body, "exchangeToken")
			until, e := deadline(r.body)
			if e != nil || len(r.body) != 2 || !secretRE.MatchString(token) || !until.After(time.Now()) {
				return ErrFailed
			}
			redeem, done := context.WithDeadline(ctx, until)
			defer done()
			session, e := api.call(redeem, "POST", "/v1/auth/sessions", map[string]string{"exchangeToken": token}, true)
			if e != nil || session.status != 201 || session.header.Get("Cache-Control") != "no-store" {
				return ErrFailed
			}
			sessionExpiry, e := deadline(session.body)
			if e != nil || !sessionExpiry.After(time.Now()) || len(session.body) != 5 || !idRE.MatchString(text(session.body, "id")) || !idRE.MatchString(text(session.body, "userId")) || text(session.body, "state") != "active" {
				return ErrFailed
			}
			cookies := (&http.Response{Header: session.header}).Cookies()
			if len(cookies) != 1 {
				return ErrFailed
			}
			c := cookies[0]
			if c.Name != "provenance_session" || !c.Secure || !c.HttpOnly || c.Domain != "" || c.Path != "/" || len(c.Value) < 16 || len(c.Value) > 4096 || c.MaxAge < 0 {
				return ErrFailed
			}
			if a.Store.Set(ctx, api.origin, "session", c.Value) != nil {
				// Best-effort revoke the newly issued credential if durable OS storage
				// fails. It is never printed or placed in a fallback store.
				cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
				defer stop()
				api.kind = "session"
				api.credential = c.Value
				_, _ = api.call(cleanup, "DELETE", "/v1/auth/session", nil, true)
				return ErrFailed
			}
			fmt.Fprintln(a.Out, "Authenticated; session stored in native credential store.")
			return nil
		default:
			return ErrFailed
		}
	}
}

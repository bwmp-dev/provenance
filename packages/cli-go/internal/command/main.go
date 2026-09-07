package command

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/bwmp-dev/provenance/packages/cli-go/internal/securestore"
	verification "github.com/bwmp-dev/provenance/packages/verification-go"
)

type App struct {
	Out, Err  io.Writer
	In        io.Reader
	Store     securestore.Store
	Transport http.RoundTripper
}
type options struct {
	origin, auth, project, candidate, jar, configuration, snapshot, version, commit, ref, attestation, key, keyID string
	tokenStdin                                                                                                    bool
	timeout                                                                                                       time.Duration
}

var idRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

func (a App) Run(ctx context.Context, args []string) int {
	if e := a.run(ctx, args); e != nil {
		fmt.Fprintln(a.Err, e)
		return 1
	}
	return 0
}
func (a App) run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return ErrInput
	}
	verb := args[0]
	args = args[1:]
	if verb == "login" {
		return ErrInput
	}
	if verb == "auth" {
		if len(args) == 0 || args[0] != "login" {
			return ErrInput
		}
		verb = "login"
		args = args[1:]
	}
	f := flag.NewFlagSet("provenance", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	var o options
	f.StringVar(&o.origin, "origin", "", "")
	f.DurationVar(&o.timeout, "timeout", 0, "")
	f.StringVar(&o.auth, "auth", "session", "")
	f.BoolVar(&o.tokenStdin, "project-token-stdin", false, "")
	for _, v := range []struct {
		p *string
		n string
	}{{&o.project, "project"}, {&o.candidate, "candidate"}, {&o.jar, "jar"}, {&o.configuration, "config"}, {&o.snapshot, "snapshot"}, {&o.version, "version"}, {&o.commit, "source-commit"}, {&o.ref, "source-ref"}, {&o.attestation, "attestation"}, {&o.key, "public-key"}, {&o.keyID, "key-id"}} {
		f.StringVar(v.p, v.n, "", "")
	}
	if f.Parse(args) != nil || f.NArg() != 0 {
		return ErrInput
	}
	if verb == "verify" {
		return a.verify(o)
	}
	if verb != "login" && verb != "test" && verb != "status" {
		return ErrInput
	}
	if o.timeout <= 0 || o.timeout > 24*time.Hour {
		return ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()
	base, e := origin(o.origin)
	if e != nil {
		return e
	}
	api := &api{origin: base, client: client(a.Transport)}
	if verb == "login" {
		if o.tokenStdin || o.auth != "session" || a.Store == nil {
			return ErrInput
		}
		return a.login(ctx, api)
	}
	if verb == "test" {
		return a.test(ctx, api, o)
	}
	if !idRE.MatchString(o.candidate) {
		return ErrInput
	}
	if e = a.authenticate(ctx, api, o); e != nil {
		return e
	}
	return a.status(ctx, api, o.candidate)
}
func (a App) authenticate(ctx context.Context, api *api, o options) error {
	if o.auth != "session" && o.auth != "project-token" {
		return ErrInput
	}
	api.kind = o.auth
	if o.tokenStdin {
		if o.auth != "project-token" || a.In == nil {
			return ErrInput
		}
		type input struct {
			data []byte
			err  error
		}
		read := make(chan input, 1)
		go func() { b, e := io.ReadAll(io.LimitReader(a.In, 4097)); read <- input{b, e} }()
		var b []byte
		var e error
		select {
		case <-ctx.Done():
			return ErrFailed
		case r := <-read:
			b, e = r.data, r.err
		}
		if e != nil || len(b) > 4096 {
			return ErrInput
		}
		api.credential = strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r")
	} else {
		if a.Store == nil || a.Store.Ready(ctx) != nil {
			return securestore.ErrUnavailable
		}
		value, e := a.Store.Get(ctx, api.origin, api.kind)
		if e != nil {
			return securestore.ErrUnavailable
		}
		api.credential = value
	}
	if len(api.credential) < 16 || len(api.credential) > 4096 || strings.ContainsAny(api.credential, "\r\n; \t") {
		return ErrInput
	}
	return nil
}
func (a App) verify(o options) error {
	if o.jar == "" || o.attestation == "" || o.key == "" || o.keyID == "" || o.origin != "" {
		return ErrInput
	}
	raw, e := readFile(o.attestation, 4*1024*1024)
	if e != nil {
		return e
	}
	keyBytes, e := readFile(o.key, 128)
	if e != nil {
		return e
	}
	pub, e := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(keyBytes)))
	if e != nil || len(pub) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(pub) != strings.TrimSpace(string(keyBytes)) {
		return ErrInput
	}
	doc, e := object(raw)
	if e != nil {
		return e
	}
	sig, ok := doc["signature"].(map[string]any)
	if !ok || text(sig, "keyId") != o.keyID {
		return ErrFailed
	}
	jar, e := os.Open(o.jar)
	if e != nil {
		return ErrInput
	}
	defer jar.Close()
	st, e := jar.Stat()
	if e != nil || !st.Mode().IsRegular() {
		return ErrInput
	}
	result, e := verification.VerifyArtifact(raw, ed25519.PublicKey(pub), jar)
	if e != nil {
		return ErrFailed
	}
	return json.NewEncoder(a.Out).Encode(result)
}
func readFile(path string, max int64) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, ErrInput
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Size() > max {
		return nil, ErrInput
	}
	b, e := io.ReadAll(io.LimitReader(f, max+1))
	if e != nil || int64(len(b)) > max {
		return nil, ErrInput
	}
	return b, nil
}

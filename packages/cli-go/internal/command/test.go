package command

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/bwmp-dev/provenance/packages/cli-go/internal/config"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var commitRE = regexp.MustCompile(`^(?:[a-f0-9]{40}|[a-f0-9]{64})$`)

func (a App) test(ctx context.Context, api *api, o options) error {
	if !idRE.MatchString(o.project) || o.jar == "" || o.configuration == "" || o.version == "" || len(o.version) > 128 {
		return ErrInput
	}
	raw, e := readFile(o.configuration, 1048576)
	if e != nil {
		return e
	}
	cfg, e := config.Parse(raw)
	if e != nil {
		return e
	}
	if o.snapshot != "" && !idRE.MatchString(o.snapshot) {
		return ErrInput
	}
	if o.snapshot == "" && (o.auth != "project-token" || !commitRE.MatchString(o.commit) || !strings.HasPrefix(o.ref, "refs/")) {
		return ErrInput
	}
	file, e := os.Open(o.jar)
	if e != nil {
		return ErrInput
	}
	defer file.Close()
	before, e := file.Stat()
	if e != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > 1073741824 || !strings.HasSuffix(filepath.Base(o.jar), ".jar") {
		return ErrInput
	}
	digest := sha256.New()
	n, e := io.Copy(digest, io.LimitReader(file, 1073741825))
	if e != nil || n != before.Size() {
		return ErrInput
	}
	sum := hex.EncodeToString(digest.Sum(nil))
	if _, e = file.Seek(0, 0); e != nil {
		return ErrInput
	}
	if e = a.authenticate(ctx, api, o); e != nil {
		return e
	}
	project := "/v1/projects/" + url.PathEscape(o.project)
	snapshot := o.snapshot
	if snapshot == "" {
		r, e := api.call(ctx, "POST", project+"/config-snapshots", map[string]any{"sourceCommit": o.commit, "sourceRef": o.ref, "rawYaml": cfg.Raw, "normalizedJson": cfg.Normalized, "schemaVersion": 1, "configurationHash": cfg.Hash}, true)
		if e != nil || r.status != 201 || text(r.body, "configurationHash") != cfg.Hash || text(r.body, "projectId") != o.project || text(r.body, "sourceCommit") != o.commit {
			return ErrFailed
		}
		snapshot = text(r.body, "id")
		if !idRE.MatchString(snapshot) {
			return ErrFailed
		}
	}
	r, e := api.call(ctx, "POST", project+"/artifacts/uploads", map[string]any{"fileName": filepath.Base(o.jar), "sizeBytes": n, "sha256": sum}, true)
	if e != nil || r.status != 201 {
		return ErrFailed
	}
	artifact, upload := text(r.body, "artifactId"), text(r.body, "uploadUrl")
	expiry, e := deadline(r.body)
	u, ue := url.Parse(upload)
	if e != nil || ue != nil || !idRE.MatchString(artifact) || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || !expiry.After(time.Now()) {
		return ErrFailed
	}
	// Same retained descriptor is hashed a second time while those exact bytes
	// go to the upload. No reopen-by-path, cookie jar, Authorization or redirects.
	h := sha256.New()
	uploadCtx, done := context.WithDeadline(ctx, expiry)
	defer done()
	request, e := http.NewRequestWithContext(uploadCtx, "PUT", upload, io.TeeReader(io.LimitReader(file, n), h))
	if e != nil {
		return ErrFailed
	}
	request.ContentLength = n
	request.Header.Set("Content-Type", "application/java-archive")
	if headers, exists := r.body["requiredHeaders"]; exists {
		m, ok := headers.(map[string]any)
		if !ok || len(m) > 64 {
			return ErrFailed
		}
		for name, value := range m {
			v, ok := value.(string)
			lower := strings.ToLower(name)
			if !ok || len(v) > 4096 || strings.ContainsAny(v, "\r\n") || (lower != "content-type" && !strings.HasPrefix(lower, "x-amz-")) {
				return ErrFailed
			}
			request.Header.Set(name, v)
		}
	}
	uploaded, e := client(a.Transport).Do(request)
	if e != nil {
		return ErrFailed
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(uploaded.Body, 4096))
	_ = uploaded.Body.Close()
	if uploaded.StatusCode < 200 || uploaded.StatusCode >= 300 {
		return ErrFailed
	}
	after, e := file.Stat()
	var extra [1]byte
	extraN, extraErr := file.Read(extra[:])
	if e != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || extraN != 0 || extraErr != io.EOF || hex.EncodeToString(h.Sum(nil)) != sum {
		return ErrFailed
	}
	completed, e := api.call(ctx, "POST", "/v1/artifacts/"+url.PathEscape(artifact)+"/complete", map[string]any{"sizeBytes": n, "sha256": sum}, true)
	if e != nil || completed.status != 202 {
		return ErrFailed
	}
	for {
		if text(completed.body, "id") != artifact || text(completed.body, "projectId") != o.project || text(completed.body, "sha256") != sum || integer(completed.body, "sizeBytes") != n {
			return ErrFailed
		}
		state := text(completed.body, "state")
		if state == "ready" {
			break
		}
		if state != "uploaded" && state != "verifying" && state != "pending" {
			return ErrFailed
		}
		if wait(ctx, time.Second) != nil {
			return ErrFailed
		}
		completed, e = api.call(ctx, "GET", "/v1/artifacts/"+url.PathEscape(artifact), nil, false)
		if e != nil || completed.status != 200 {
			return ErrFailed
		}
	}
	candidate, e := api.call(ctx, "POST", project+"/release-candidates", map[string]any{"artifactId": artifact, "configurationSnapshotId": snapshot, "configurationHash": cfg.Hash, "version": o.version}, true)
	if e != nil || candidate.status != 201 || text(candidate.body, "artifactId") != artifact || text(candidate.body, "configurationHash") != cfg.Hash || text(candidate.body, "projectId") != o.project || !idRE.MatchString(text(candidate.body, "id")) {
		return ErrFailed
	}
	return json.NewEncoder(a.Out).Encode(map[string]string{"candidateId": text(candidate.body, "id"), "projectId": o.project, "artifactId": artifact, "configurationSnapshotId": snapshot, "configurationHash": cfg.Hash})
}

// Independent canonical/digest check of the closed-ASCII synthetic vector.
// Not a production schema validator, immutable-plan consumer or issuer.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
)

func digest(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
func closed(v any) bool {
	switch v := v.(type) {
	case nil, bool:
		return true
	case string:
		for _, r := range v {
			if r < 32 || r > 126 {
				return false
			}
		}
		return true
	case json.Number:
		n, e := strconv.ParseInt(string(v), 10, 64)
		return e == nil && n >= -9007199254740991 && n <= 9007199254740991
	case []any:
		for _, x := range v {
			if !closed(x) {
				return false
			}
		}
		return true
	case map[string]any:
		for k, x := range v {
			if !closed(k) || !closed(x) {
				return false
			}
		}
		return true
	default:
		return false
	}
}
func canonical(v any) ([]byte, error) {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if err := e.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}
func check() error {
	if len(os.Args) != 2 {
		return fmt.Errorf("vector argument")
	}
	raw, e := os.ReadFile(os.Args[1])
	if e != nil {
		return e
	}
	var vector struct{ Canonical, SHA256 string }
	if e = json.Unmarshal(raw, &vector); e != nil {
		return e
	}
	if digest([]byte(vector.Canonical)) != vector.SHA256 {
		return fmt.Errorf("envelope digest")
	}
	var value map[string]any
	decoder := json.NewDecoder(bytes.NewBufferString(vector.Canonical))
	decoder.UseNumber()
	if e = decoder.Decode(&value); e != nil {
		return e
	}
	if !closed(value) {
		return fmt.Errorf("fixture domain")
	}
	encoded, e := canonical(value)
	if e != nil {
		return e
	}
	if string(encoded) != vector.Canonical {
		return fmt.Errorf("canonical bytes")
	}
	if value["schemaVersion"] != "provenance.execution-evidence/v2" {
		return fmt.Errorf("version")
	}
	assertions, ok := value["assertions"].([]any)
	if !ok {
		return fmt.Errorf("assertions")
	}
	literal := 0
	for _, item := range assertions {
		a, ok := item.(map[string]any)
		if !ok {
			return fmt.Errorf("assertion")
		}
		evidence, ok := a["evidence"].(map[string]any)
		if !ok {
			return fmt.Errorf("preimage")
		}
		for _, k := range []string{"id", "type", "outcome"} {
			if a[k] != evidence[k] {
				return fmt.Errorf("preimage identity")
			}
		}
		encoded, e = canonical(evidence)
		if e != nil {
			return e
		}
		if digest(encoded) != a["evidenceSha256"] {
			return fmt.Errorf("preimage digest")
		}
		if a["type"] == "console-contains" {
			literal++
		}
	}
	if literal == 0 {
		return fmt.Errorf("missing literal fixture")
	}
	fmt.Printf("%s\n", vector.SHA256)
	return nil
}
func main() {
	if check() != nil {
		fmt.Fprintln(os.Stderr, "golden check failed")
		os.Exit(1)
	}
}

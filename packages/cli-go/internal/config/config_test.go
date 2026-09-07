package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuthoritativeSchemaAndGoldenParity(t *testing.T) {
	root := "../../../.."
	raw, e := os.ReadFile(filepath.Join(root, "schemas/config/v1/schema.json"))
	if e != nil || !bytes.Equal(raw, schema) {
		t.Fatal("embedded schema differs", e)
	}
	files, e := filepath.Glob(filepath.Join(root, "schemas/fixtures/config/valid/*.yml"))
	if e != nil || len(files) == 0 {
		t.Fatal("missing fixtures")
	}
	for _, path := range files {
		t.Run(filepath.Base(path), func(t *testing.T) {
			raw, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			got, e := Normalize(raw)
			if e != nil {
				t.Fatal(e)
			}
			cmd := exec.Command("node", "--input-type=module", "-e", `import {readFileSync} from 'node:fs';import {parseConfiguration,normalizeConfiguration} from './packages/config-schema/dist/index.js';process.stdout.write(normalizeConfiguration(parseConfiguration(readFileSync(process.argv[1],'utf8'))));`, path)
			abs, _ := filepath.Abs(path)
			cmd.Args[len(cmd.Args)-1] = abs
			cmd.Dir = root
			out, e := cmd.CombinedOutput()
			if e != nil {
				t.Fatalf("actual JS reference required: %v %s", e, out)
			}
			if string(out) != got.Normalized {
				t.Fatal("cross-language normalization differs")
			}
		})
	}
	bad, _ := filepath.Glob(filepath.Join(root, "schemas/fixtures/config/invalid/*.yml"))
	for _, path := range bad {
		raw, _ := os.ReadFile(path)
		if _, e := Normalize(raw); e == nil {
			t.Errorf("invalid fixture accepted %s", filepath.Base(path))
		}
	}
}

func TestUnicodeRegexAndScalarParity(t *testing.T) {
	base, e := os.ReadFile("../../../../schemas/fixtures/config/valid/self-hosted-unrestricted.yml")
	if e != nil {
		t.Fatal(e)
	}
	for name, want := range map[string]string{"regexpp.cjs": "8f9526195a26cb0d47a48528e61f0083596d397092296a44fc1c1ac470aba336", "LICENSE": "fcf6eabf68ca96988a6b506b4fdc6cc32535d80eb2e11c79724af5ac6f50262b"} {
		b, e := os.ReadFile("regexpp/" + name)
		if e != nil || fmt.Sprintf("%x", sha256.Sum256(b)) != want {
			t.Fatal("vendored dependency pin mismatch", name, e)
		}
	}
	patterns := []string{`abc`, `\a`, `\q`, `\u{1F600}`, `\p{Script=Greek}`, `(?<name>a)\k<name>`, `(?<=a)b`, `(?i)a`, `[z-a]`, `\8`, `\0`, `\01`, `a{2,1}`, `[\-]`, `\-`, `[a&&b]`, `(?:a|b)*`, `(?<α>a)`}
	for _, p := range patterns {
		t.Run(p, func(t *testing.T) {
			cmd := exec.Command("node", "--input-type=module", "-e", `try{new RegExp(process.argv[1],"u");process.stdout.write("valid")}catch{process.stdout.write("invalid")}`, p)
			out, err := cmd.Output()
			if err != nil {
				t.Fatal(err)
			}
			if (validateRegex(p) == nil) != (string(out) == "valid") {
				t.Fatalf("JS Unicode regex acceptance differs for %q", p)
			}
			entry, _ := json.Marshal([]any{map[string]any{"id": "regex-parity", "command": "version", "timeoutSeconds": 10, "assertions": []any{map[string]any{"stream": "combined", "operator": "regex", "pattern": p, "match": "present"}}}})
			yamlText := strings.Replace(string(base), "console: []", "console: "+string(entry), 1)
			encoded, _ := json.Marshal(yamlText)
			reference := exec.Command("node", "--input-type=module", "-e", `import{parseConfiguration,normalizeConfiguration}from './packages/config-schema/dist/index.js';try{process.stdout.write(normalizeConfiguration(parseConfiguration(JSON.parse(process.argv[1]))))}catch{process.exit(3)}`, string(encoded))
			reference.Dir = "../../../.."
			normalized, jsErr := reference.Output()
			got, goErr := Normalize([]byte(yamlText))
			if (jsErr == nil) != (goErr == nil) || (jsErr == nil && got.Normalized != string(normalized)) {
				t.Fatalf("released normalizer regex parity differs for %q", p)
			}
		})
	}
	raw, err := os.ReadFile("../../../../schemas/fixtures/config/valid/self-hosted-unrestricted.yml")
	if err != nil {
		t.Fatal(err)
	}
	for _, replacement := range []string{"cpuCores: 1e0", "cpuCores: 0x2", "cpuCores: .inf", "cpuCores: 01", "cpuCores: 0o2", "cpuCores: 1_0"} {
		modified := strings.Replace(string(raw), "cpuCores: 1.5", replacement, 1)
		encoded, _ := json.Marshal(modified)
		cmd := exec.Command("node", "--input-type=module", "-e", `import{parseConfiguration,normalizeConfiguration}from './packages/config-schema/dist/index.js';try{process.stdout.write(normalizeConfiguration(parseConfiguration(JSON.parse(process.argv[1]))))}catch{process.exit(3)}`, string(encoded))
		cmd.Dir = "../../../.."
		out, err := cmd.Output()
		got, goErr := Normalize([]byte(modified))
		if (err == nil) != (goErr == nil) || (err == nil && got.Normalized != string(out)) {
			t.Fatalf("scalar parity differs for %s", replacement)
		}
	}
}
func TestStrictYAMLAndTestOnly(t *testing.T) {
	raw, e := os.ReadFile("../../../../schemas/fixtures/config/valid/self-hosted-unrestricted.yml")
	if e != nil {
		t.Fatal(e)
	}
	if _, e := Parse(raw); e != nil {
		t.Fatal(e)
	}
	for _, extra := range []string{"\nunknown: true\n", "\nrelease: {mode: test-only, targets: []}\n", "\n---\n{}\n", "\nx: &anchor [1]\ny: *anchor\n", "\nx: !foo value\n"} {
		if _, e := Parse(append(append([]byte{}, raw...), extra...)); e == nil {
			t.Fatal("invalid YAML accepted")
		}
	}
	manual, _ := os.ReadFile("../../../../schemas/fixtures/config/valid/hosted.yml")
	if _, e := Parse(manual); e == nil {
		t.Fatal("manual mode accepted by test")
	}
}

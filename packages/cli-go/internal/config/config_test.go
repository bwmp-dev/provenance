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

func TestPinnedTestSecretSelections(t *testing.T) {
	raw, err := os.ReadFile("../../../../schemas/fixtures/config/valid/hosted.normalized.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		selection string
		valid     bool
	}{
		{`{}`, true}, {`{"token":1,"api.token":9007199254740991}`, true},
		{`{"token":0}`, false}, {`{"token":"latest"}`, false},
		{`{"token":9007199254740992}`, false}, {`{"../token":1}`, false},
		{`{"TOKEN":1}`, false}, {`{"token":1.5}`, false}, {`null`, false},
	} {
		var doc map[string]any
		if json.Unmarshal(raw, &doc) != nil {
			t.Fatal("fixture invalid")
		}
		var selection any
		if json.Unmarshal([]byte(tc.selection), &selection) != nil {
			t.Fatal("case invalid")
		}
		doc["tests"].(map[string]any)["secrets"] = selection
		input, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		_, err = Normalize(input)
		if (err == nil) != tc.valid {
			t.Fatalf("selection validity differs: %s", tc.selection)
		}
	}
}

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
	bad, _ := filepath.Glob(filepath.Join(root, "schemas/fixtures/config/invalid-yaml/*.yml"))
	if len(bad) == 0 {
		t.Fatal("missing invalid YAML corpus")
	}
	for _, path := range bad {
		raw, _ := os.ReadFile(path)
		if _, e := Normalize(raw); e == nil {
			t.Errorf("invalid fixture accepted %s", filepath.Base(path))
		}
	}
}

func TestActualInvalidMutationCorpus(t *testing.T) {
	const root = "../../../../schemas/fixtures/config/"
	original, err := os.ReadFile(root + "valid/hosted.normalized.json")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(root + "invalid/cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name  string
		Path  []any
		Value any
	}
	if json.Unmarshal(raw, &cases) != nil || len(cases) == 0 {
		t.Fatal("missing mutation corpus")
	}
	for _, fixture := range cases {
		t.Run(fixture.Name, func(t *testing.T) {
			var value any
			if json.Unmarshal(original, &value) != nil || len(fixture.Path) == 0 {
				t.Fatal("invalid base or path")
			}
			target := value
			for _, part := range fixture.Path[:len(fixture.Path)-1] {
				switch key := part.(type) {
				case string:
					target = target.(map[string]any)[key]
				case float64:
					target = target.([]any)[int(key)]
				default:
					t.Fatal("unsupported fixture path")
				}
			}
			switch key := fixture.Path[len(fixture.Path)-1].(type) {
			case string:
				target.(map[string]any)[key] = fixture.Value
			case float64:
				target.([]any)[int(key)] = fixture.Value
			default:
				t.Fatal("unsupported fixture path")
			}
			mutated, _ := json.Marshal(value)
			if _, err := Normalize(mutated); err == nil {
				t.Fatal("invalid released mutation accepted")
			}
			reference := exec.Command("node", "--input-type=module", "-e", `import{parseConfiguration}from './packages/config-schema/dist/index.js';try{parseConfiguration(process.argv[1]);process.exit(0)}catch{process.exit(3)}`, string(mutated))
			reference.Dir = "../../../.."
			if err := reference.Run(); err == nil {
				t.Fatal("reference unexpectedly accepted mutation")
			} else if e, ok := err.(*exec.ExitError); !ok || e.ExitCode() != 3 {
				t.Fatal("reference unavailable", err)
			}
		})
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

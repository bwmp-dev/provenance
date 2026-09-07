// Package config consumes the unchanged v1 schema and normalization contract.
package config

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/dlclark/regexp2"
	"github.com/dop251/goja"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"go.yaml.in/yaml/v3"
)

var ErrInvalid = errors.New("invalid test-only configuration")

//go:embed schema.json
var schema []byte

//go:embed regexpp/regexpp.cjs
var regexppSource string
var regexppProgram, regexppCompileError = goja.Compile("regexpp-4.12.2", regexppSource, false)

// YAML 1.2 core numeric spellings, matching the pinned yaml 2.9.0 reference.
var coreNumber = regexp.MustCompile(`^(?:0o[0-7]+|0x[0-9a-fA-F]+|[-+]?[0-9]+|[-+]?(?:\.[0-9]+|[0-9]+(?:\.[0-9]*)?)(?:[eE][-+]?[0-9]+)?)$`)

type Document struct {
	Raw, Normalized string
	Hash            string
}
type regex struct{ pattern string }

func (r regex) String() string { return r.pattern }

// Matching is needed only for pinned schema patterns. Customer assertion
// patterns are format-validated, never executed by configuration loading.
func (r regex) MatchString(s string) bool {
	re, e := regexp2.Compile(r.pattern, regexp2.ECMAScript|regexp2.Unicode)
	if e != nil {
		return false
	}
	re.MatchTimeout = 100 * time.Millisecond
	ok, e := re.MatchString(s)
	return e == nil && ok
}

type offline struct{}

func (offline) Load(string) (any, error) { return nil, ErrInvalid }

func Parse(raw []byte) (Document, error) {
	d, e := Normalize(raw)
	if e != nil {
		return Document{}, e
	}
	var v map[string]any
	if json.Unmarshal([]byte(d.Normalized), &v) != nil {
		return Document{}, ErrInvalid
	}
	release, ok := v["release"].(map[string]any)
	if !ok || release["mode"] != "test-only" {
		return Document{}, ErrInvalid
	}
	return d, nil
}
func Normalize(raw []byte) (Document, error) {
	if len(raw) == 0 || len(raw) > 1048576 || !utf8.Valid(raw) {
		return Document{}, ErrInvalid
	}
	d := yaml.NewDecoder(bytes.NewReader(raw))
	var root yaml.Node
	if d.Decode(&root) != nil || len(root.Content) != 1 {
		return Document{}, ErrInvalid
	}
	var extra yaml.Node
	if d.Decode(&extra) != io.EOF {
		return Document{}, ErrInvalid
	}
	budget := 200000
	v, e := convert(root.Content[0], 0, &budget)
	if e != nil {
		return Document{}, ErrInvalid
	}
	var s any
	if json.Unmarshal(schema, &s) != nil {
		return Document{}, ErrInvalid
	}
	c := jsonschema.NewCompiler()
	c.UseLoader(offline{})
	c.AssertFormat()
	checked := map[string]error{}
	c.UseRegexpEngine(func(p string) (jsonschema.Regexp, error) {
		err, seen := checked[p]
		if !seen {
			err = validateRegex(p)
			checked[p] = err
		}
		if err != nil {
			return nil, err
		}
		return regex{p}, nil
	})
	if c.AddResource("https://cli.invalid/config", s) != nil {
		return Document{}, ErrInvalid
	}
	compiled, e := c.Compile("https://cli.invalid/config")
	if e != nil || compiled.Validate(v) != nil {
		return Document{}, ErrInvalid
	}
	b := canonical(v)
	h := sha256.Sum256([]byte(b))
	return Document{string(raw), b, hex.EncodeToString(h[:])}, nil
}

// The released contract uses JavaScript RegExp with the Unicode flag, not
// regexp2's more permissive .NET grammar. Pass the pattern as a value to the
// fixed parser; no customer text is evaluated as JavaScript source.
func validateRegex(pattern string) error {
	if len(pattern) > 4000 || regexppCompileError != nil {
		return ErrInvalid
	}
	vm := goja.New()
	stop := time.AfterFunc(100*time.Millisecond, func() { vm.Interrupt(ErrInvalid) })
	defer stop.Stop()
	if vm.Set("exports", vm.NewObject()) != nil {
		return ErrInvalid
	}
	if _, err := vm.RunProgram(regexppProgram); err != nil {
		return ErrInvalid
	}
	validator, err := vm.RunString(`(function(pattern){new exports.RegExpValidator({ecmaVersion:2025}).validatePattern(pattern,0,pattern.length,{unicode:true});})`)
	if err != nil {
		return ErrInvalid
	}
	call, ok := goja.AssertFunction(validator)
	if !ok {
		return ErrInvalid
	}
	_, err = call(goja.Undefined(), vm.ToValue(pattern))
	if err != nil {
		return ErrInvalid
	}
	return nil
}
func convert(n *yaml.Node, depth int, budget *int) (any, error) {
	*budget--
	if depth > 64 || *budget < 0 || n.Kind == yaml.AliasNode {
		return nil, ErrInvalid
	}
	if n.Style&yaml.TaggedStyle != 0 && !strings.HasPrefix(n.Tag, "tag:yaml.org,2002:") && !strings.HasPrefix(n.Tag, "!!") {
		return nil, ErrInvalid
	}
	switch n.Kind {
	case yaml.MappingNode:
		if n.Tag != "!!map" {
			return nil, ErrInvalid
		}
		m := map[string]any{}
		for i := 0; i < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind != yaml.ScalarNode || k.Tag != "!!str" {
				return nil, ErrInvalid
			}
			if _, ok := m[k.Value]; ok {
				return nil, ErrInvalid
			}
			v, e := convert(n.Content[i+1], depth+1, budget)
			if e != nil {
				return nil, e
			}
			m[k.Value] = v
		}
		return m, nil
	case yaml.SequenceNode:
		if n.Tag != "!!seq" {
			return nil, ErrInvalid
		}
		a := make([]any, 0, len(n.Content))
		for _, x := range n.Content {
			v, e := convert(x, depth+1, budget)
			if e != nil {
				return nil, e
			}
			a = append(a, v)
		}
		return a, nil
	case yaml.ScalarNode:
		switch n.Tag {
		case "!!str":
			return n.Value, nil
		case "!!timestamp":
			if n.Style&yaml.TaggedStyle != 0 {
				return nil, ErrInvalid
			}
			return n.Value, nil
		case "!!null":
			return nil, nil
		case "!!bool":
			if !strings.EqualFold(n.Value, "true") && !strings.EqualFold(n.Value, "false") {
				return nil, ErrInvalid
			}
			return strings.EqualFold(n.Value, "true"), nil
		case "!!int", "!!float":
			raw := n.Value
			if !coreNumber.MatchString(raw) && !strings.Contains(strings.ToLower(raw), ".inf") && !strings.Contains(strings.ToLower(raw), ".nan") {
				if n.Style&yaml.TaggedStyle != 0 {
					return nil, ErrInvalid
				}
				return raw, nil
			}
			if strings.Contains(raw, "_") {
				return nil, ErrInvalid
			}
			var value float64
			var e error
			if strings.HasPrefix(raw, "0x") || strings.HasPrefix(raw, "0o") {
				var i uint64
				i, e = strconv.ParseUint(raw[2:], map[string]int{"0x": 16, "0o": 8}[raw[:2]], 64)
				value = float64(i)
			} else {
				value, e = strconv.ParseFloat(raw, 64)
			}
			if e != nil || math.IsNaN(value) || math.IsInf(value, 0) {
				return nil, ErrInvalid
			}
			return value, nil
		}
	}
	return nil, ErrInvalid
}
func quote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 32 {
				b.WriteString(`\u00`)
				b.WriteString(hex.EncodeToString([]byte{byte(r)}))
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}
func canonical(v any) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case bool:
		if x {
			return "true"
		}
		return "false"
	case string:
		return quote(x)
	case float64:
		if x == 0 {
			return "0"
		}
		b, _ := json.Marshal(x)
		return string(b)
	case []any:
		a := make([]string, len(x))
		for i, v := range x {
			a[i] = canonical(v)
		}
		return "[" + strings.Join(a, ",") + "]"
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			a, b := utf16.Encode([]rune(keys[i])), utf16.Encode([]rune(keys[j]))
			for n := 0; n < len(a) && n < len(b); n++ {
				if a[n] != b[n] {
					return a[n] < b[n]
				}
			}
			return len(a) < len(b)
		})
		a := make([]string, len(keys))
		for i, k := range keys {
			a[i] = quote(k) + ":" + canonical(x[k])
		}
		return "{" + strings.Join(a, ",") + "}"
	}
	panic("invalid internal canonical value")
}

package command_test

import (
	"encoding/json"
	"net/http"
	"os"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"go.yaml.in/yaml/v3"
)

func assertReleasedPagination(t *testing.T, r *http.Request, wantCursor string) {
	t.Helper()
	query := r.URL.Query()
	for name, values := range query {
		if (name != "limit" && name != "cursor") || len(values) != 1 {
			t.Errorf("unexpected pagination parameter %q", name)
		}
	}
	if len(query["limit"]) != 1 || query.Get("limit") != "100" {
		t.Error("released bounded limit=100 missing")
	}
	if wantCursor == "" {
		if _, present := query["cursor"]; present {
			t.Error("initial page must omit cursor")
		}
	} else if len(query["cursor"]) != 1 || query.Get("cursor") != wantCursor {
		t.Error("continuation did not preserve exact nextCursor")
	}
}

func assertReleasedShape(t *testing.T, name string, value any) {
	t.Helper()
	raw, err := os.ReadFile("../../../../openapi/provenance.v1.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var document any
	if err = yaml.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	if err = compiler.AddResource("https://contract.invalid/openapi", document); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile("https://contract.invalid/openapi#/components/schemas/" + name)
	if err != nil {
		t.Fatal(err)
	}
	// Marshal first to turn all integer fixture types into the actual JSON model.
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var jsonValue any
	if err = json.Unmarshal(encoded, &jsonValue); err != nil {
		t.Fatal(err)
	}
	if err = schema.Validate(jsonValue); err != nil {
		t.Fatalf("released %s mismatch: %v", name, err)
	}
}

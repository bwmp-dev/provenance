package command_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"go.yaml.in/yaml/v3"
)

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

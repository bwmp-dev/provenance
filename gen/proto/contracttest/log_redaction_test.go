package contracttest

import (
	"bytes"
	"encoding/json"
	"testing"

	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestCompleteLogRedactionMetadataIsAdditive(t *testing.T) {
	value := &runnerv1.LogObject{}
	field := value.ProtoReflect().Descriptor().Fields().ByName("redacted")
	if field == nil || field.Number() != 10 || field.Kind() != protoreflect.BoolKind {
		t.Fatal("complete log needs an additive redacted boolean at unreserved field 10")
	}
	if value.ProtoReflect().Get(field).Bool() {
		t.Fatal("legacy absent metadata changed")
	}
	value.ProtoReflect().Set(field, protoreflect.ValueOfBool(true))
	wire, err := proto.Marshal(value)
	if err != nil || !bytes.Equal(wire, []byte{0x50, 1}) {
		t.Fatal("redaction wire identity changed")
	}
	var decoded runnerv1.LogObject
	if err := proto.Unmarshal(wire, &decoded); err != nil || !decoded.ProtoReflect().Get(field).Bool() {
		t.Fatal("terminal redaction fact lost in wire roundtrip")
	}
	raw, err := protojson.Marshal(&decoded)
	var document map[string]any
	if err != nil || json.Unmarshal(raw, &document) != nil || document["redacted"] != true {
		t.Fatal("durable JSON carrier lost redaction fact")
	}
	for number := protoreflect.FieldNumber(5); number <= 9; number++ {
		if !value.ProtoReflect().Descriptor().ReservedRanges().Has(number) {
			t.Fatal("historical field reservation changed")
		}
	}
}

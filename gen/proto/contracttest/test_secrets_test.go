package contracttest

import (
	"bytes"
	"testing"

	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
)

func TestTestSecretsWireSeparation(t *testing.T) {
	if runnerv1.ProtocolFeature_PROTOCOL_FEATURE_TEST_SECRETS_V1 != 8 {
		t.Fatal("feature number changed")
	}
	ref := &runnerv1.TestSecretReference{SecretId: "84000000-0000-0000-0000-000000000001", Name: "token", Version: 9007199254740991}
	job := &runnerv1.JobSpecification{TestSecrets: []*runnerv1.TestSecretReference{ref}}
	wire, err := proto.Marshal(job)
	if err != nil {
		t.Fatal(err)
	}
	var decodedJob runnerv1.JobSpecification
	if proto.Unmarshal(wire, &decodedJob) != nil || !proto.Equal(job, &decodedJob) {
		t.Fatal("immutable selection changed on wire")
	}
	fields := ref.ProtoReflect().Descriptor().Fields()
	if fields.Len() != 3 || fields.ByName("value") != nil || fields.ByName("digest") != nil {
		t.Fatal("reference must remain metadata-only")
	}
	value := bytes.Repeat([]byte{0}, 65536)
	delivery := &runnerv1.GatewayMessage{Payload: &runnerv1.GatewayMessage_TestSecretsDelivery{TestSecretsDelivery: &runnerv1.TestSecretsDelivery{RequestMessageId: "request-1", Secrets: []*runnerv1.TestSecretValue{{Reference: ref, Value: value}}}}}
	wire, err = proto.Marshal(delivery)
	if err != nil || len(wire) <= 65536 || len(wire) > 98304 {
		t.Fatal("maximum value does not fit negotiated envelope")
	}
	var decoded runnerv1.GatewayMessage
	if proto.Unmarshal(wire, &decoded) != nil || !proto.Equal(delivery, &decoded) {
		t.Fatal("ephemeral value changed on wire")
	}
	clear(decoded.GetTestSecretsDelivery().Secrets[0].Value)
	clear(wire)
	request := &runnerv1.RunnerMessage{Payload: &runnerv1.RunnerMessage_TestSecretsRequest{TestSecretsRequest: &runnerv1.TestSecretsRequest{Lease: &runnerv1.LeaseIdentity{LeaseId: "lease"}, Attempt: &runnerv1.AttemptIdentity{AttemptId: "attempt"}}}}
	wire, err = proto.Marshal(request)
	var decodedRequest runnerv1.RunnerMessage
	if err != nil || proto.Unmarshal(wire, &decodedRequest) != nil || !proto.Equal(request, &decodedRequest) {
		t.Fatal("request identity changed on wire")
	}
	if (&runnerv1.JobSpecification{}).GetTestSecrets() != nil {
		t.Fatal("legacy job acquired secret selection")
	}
}

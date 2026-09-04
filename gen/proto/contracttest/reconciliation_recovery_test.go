package contracttest

import (
	"testing"
	"time"

	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestRestartUploadRecoveryFeatureDescriptorAndRoundTrip(t *testing.T) {
	feature := runnerv1.ProtocolFeature_PROTOCOL_FEATURE_RESTART_UPLOAD_RECOVERY
	if feature.Number() != protoreflect.EnumNumber(4) {
		t.Fatalf("restart upload recovery feature number = %d, want 4", feature.Number())
	}
	descriptor := feature.Type().Descriptor().Values().ByNumber(feature.Number())
	if descriptor.Name() != "PROTOCOL_FEATURE_RESTART_UPLOAD_RECOVERY" {
		t.Fatalf("restart upload recovery feature name = %s", descriptor.Name())
	}

	capabilities := &runnerv1.Capabilities{Features: []runnerv1.ProtocolFeature{
		runnerv1.ProtocolFeature_PROTOCOL_FEATURE_DURABLE_LEASE_ACKNOWLEDGEMENTS,
		feature,
	}}
	wire, err := proto.Marshal(capabilities)
	if err != nil {
		t.Fatalf("marshal negotiated recovery feature: %v", err)
	}
	var decoded runnerv1.Capabilities
	if err := proto.Unmarshal(wire, &decoded); err != nil {
		t.Fatalf("unmarshal negotiated recovery feature: %v", err)
	}
	if !proto.Equal(capabilities, &decoded) {
		t.Fatalf("negotiated recovery features changed during round trip: got %v", &decoded)
	}
}

func TestLeaseReconciliationRecoveryUploadRoundTrip(t *testing.T) {
	expiresAt := timestamppb.New(time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC))
	reconciliation := &runnerv1.LeaseReconciliation{
		Lease: &runnerv1.LeaseIdentity{
			LeaseId:     "lease-recovery",
			JobId:       "job-recovery",
			ExecutionId: "execution-recovery",
			ExpiresAt:   timestamppb.New(time.Date(2030, time.January, 2, 4, 0, 0, 0, time.UTC)),
		},
		Attempt: &runnerv1.AttemptIdentity{
			AttemptId:          "attempt-recovery",
			AttemptNumber:      2,
			ReleaseCandidateId: "candidate-recovery",
			MatrixEntryId:      "matrix-recovery",
		},
		Disposition: runnerv1.RunnerMessageDisposition_RUNNER_MESSAGE_DISPOSITION_APPLIED,
		Status:      runnerv1.LeaseStatus_LEASE_STATUS_ACTIVE,
		Phase:       runnerv1.JobPhase_JOB_PHASE_RUNNING,
		CompleteLogUpload: &runnerv1.ObjectUpload{
			Uri:         "https://object.invalid/ephemeral-recovery-capability",
			ContentType: "application/gzip",
			ExpiresAt:   expiresAt,
		},
	}

	wire, err := proto.Marshal(reconciliation)
	if err != nil {
		t.Fatalf("marshal recovery reconciliation: %v", err)
	}
	var decoded runnerv1.LeaseReconciliation
	if err := proto.Unmarshal(wire, &decoded); err != nil {
		t.Fatalf("unmarshal recovery reconciliation: %v", err)
	}
	if !proto.Equal(reconciliation, &decoded) {
		t.Fatalf("recovery reconciliation changed during round trip: got %v", &decoded)
	}
	if decoded.GetCompleteLogUpload().GetUri() != reconciliation.GetCompleteLogUpload().GetUri() {
		t.Fatal("recovery upload capability did not round trip")
	}
}

func TestLeaseReconciliationWithoutRecoveryUploadRemainsValid(t *testing.T) {
	legacy := &runnerv1.LeaseReconciliation{
		Lease:   &runnerv1.LeaseIdentity{LeaseId: "lease-legacy"},
		Attempt: &runnerv1.AttemptIdentity{AttemptId: "attempt-legacy"},
		Status:  runnerv1.LeaseStatus_LEASE_STATUS_ACTIVE,
		Phase:   runnerv1.JobPhase_JOB_PHASE_RUNNING,
	}

	wire, err := proto.Marshal(legacy)
	if err != nil {
		t.Fatalf("marshal reconciliation without recovery upload: %v", err)
	}
	var decoded runnerv1.LeaseReconciliation
	if err := proto.Unmarshal(wire, &decoded); err != nil {
		t.Fatalf("unmarshal reconciliation without recovery upload: %v", err)
	}
	if decoded.GetCompleteLogUpload() != nil {
		t.Fatalf("absent recovery upload became present: %v", decoded.GetCompleteLogUpload())
	}
}

func TestLeaseReconciliationRecoveryUploadUsesCompatibleField(t *testing.T) {
	field := (&runnerv1.LeaseReconciliation{}).ProtoReflect().Descriptor().Fields().ByName("complete_log_upload")
	if field == nil {
		t.Fatal("complete_log_upload descriptor is absent")
	}
	if field.Number() != protoreflect.FieldNumber(16) {
		t.Fatalf("complete_log_upload field number = %d, want 16", field.Number())
	}
	if field.Message().FullName() != "provenance.runner.v1.ObjectUpload" {
		t.Fatalf("complete_log_upload type = %s, want ObjectUpload", field.Message().FullName())
	}
	if !field.HasPresence() {
		t.Fatal("complete_log_upload must retain message presence")
	}
}

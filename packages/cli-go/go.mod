module github.com/bwmp-dev/provenance/packages/cli-go

go 1.25.13

require (
	github.com/99designs/keyring v1.2.2
	github.com/bwmp-dev/provenance/packages/verification-go v0.0.0-00010101000000-000000000000
	github.com/dlclark/regexp2 v1.12.0
	github.com/dop251/goja v0.0.0-20260906210903-70ad66ec7ce4
	github.com/godbus/dbus v0.0.0-20190726142602-4481cbc300e2
	github.com/santhosh-tekuri/jsonschema/v6 v6.0.3
	go.yaml.in/yaml/v3 v3.0.4
)

require (
	github.com/99designs/go-keychain v0.0.0-20191008050251-8e49817e8af4 // indirect
	github.com/danieljoos/wincred v1.1.2 // indirect
	github.com/dlclark/regexp2/v2 v2.5.2 // indirect
	github.com/dvsekhvalnov/jose2go v1.7.0 // indirect
	github.com/go-sourcemap/sourcemap v2.1.3+incompatible // indirect
	github.com/google/pprof v0.0.0-20230207041349-798e818bf904 // indirect
	github.com/gsterjov/go-libsecret v0.0.0-20161001094733-a6f4afe4910c // indirect
	github.com/mtibben/percent v0.2.1 // indirect
	golang.org/x/sys v0.3.0 // indirect
	golang.org/x/term v0.3.0 // indirect
	golang.org/x/text v0.41.0 // indirect
)

// Source-checkout linkage, not a published nested-module version.
replace github.com/bwmp-dev/provenance/packages/verification-go => ../verification-go

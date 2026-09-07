//go:build linux

package securestore

import (
	"context"
	"github.com/godbus/dbus"
	"os"
	"testing"
	"time"
)

func TestNativeSecretService(t *testing.T) {
	if os.Getenv("CLI_NATIVE_STORE_REQUIRED") != "1" {
		t.Skip("requires explicit disposable Secret Service fixture")
	}
	if os.Getuid() == 0 {
		t.Fatal("native acceptance requires the isolated non-root fixture user")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s := New()
	if e := s.Ready(ctx); e != nil {
		t.Fatal("native preflight", e)
	}
	origin := "https://native-fixture.invalid"
	key := origin + "/session"
	defer s.ring.Remove(key)
	value := "synthetic-native-session-value"
	if e := s.Set(ctx, origin, "session", value); e != nil {
		t.Fatal(e)
	}
	got, e := s.Get(ctx, origin, "session")
	if e != nil || got != value {
		t.Fatal("native roundtrip", e)
	}
	if _, e = s.Get(ctx, "https://foreign.invalid", "session"); e == nil {
		t.Fatal("origin isolation")
	}
	if _, e = s.Get(ctx, origin, "project-token"); e == nil {
		t.Fatal("credential kind isolation")
	}
	if e = s.ring.Remove(key); e != nil {
		t.Fatal("native remove", e)
	}
	conn, e := dbus.SessionBus()
	if e != nil {
		t.Fatal(e)
	}
	obj := conn.Object("org.freedesktop.secrets", "/org/freedesktop/secrets")
	var path dbus.ObjectPath
	if e = obj.Call("org.freedesktop.Secret.Service.ReadAlias", 0, "default").Store(&path); e != nil {
		t.Fatal(e)
	}
	if e = obj.Call("org.freedesktop.Secret.Service.Lock", 0, []dbus.ObjectPath{path}).Err; e != nil {
		t.Fatal(e)
	}
	if e = New().Ready(ctx); e == nil {
		t.Fatal("locked native store accepted")
	}
}

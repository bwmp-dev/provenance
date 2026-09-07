package securestore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"runtime"
	"strings"
	"sync"

	"github.com/99designs/keyring"
	"github.com/godbus/dbus"
)

var ErrUnavailable = errors.New("native credential store unavailable or locked")

type Store interface {
	Ready(context.Context) error
	Get(context.Context, string, string) (string, error)
	Set(context.Context, string, string, string) error
}
type Native struct {
	mu   sync.Mutex
	ring keyring.Keyring
}

func New() *Native { return &Native{} }
func (n *Native) open() error {
	var backend keyring.BackendType
	collection := ""
	switch runtime.GOOS {
	case "linux":
		backend = keyring.SecretServiceBackend
		conn, e := dbus.SessionBusPrivate()
		if e != nil {
			return ErrUnavailable
		}
		defer conn.Close()
		if conn.Auth(nil) != nil || conn.Hello() != nil {
			return ErrUnavailable
		}
		var path dbus.ObjectPath
		if conn.Object("org.freedesktop.secrets", "/org/freedesktop/secrets").Call("org.freedesktop.Secret.Service.ReadAlias", 0, "default").Store(&path) != nil || path == "/" {
			return ErrUnavailable
		}
		value, e := conn.Object("org.freedesktop.secrets", path).GetProperty("org.freedesktop.Secret.Collection.Locked")
		if e != nil || value.Value() != false {
			return ErrUnavailable
		}
		collection = strings.TrimPrefix(string(path), "/org/freedesktop/secrets/collection/")
		if collection == string(path) || collection == "" || strings.ContainsAny(collection, "/_") {
			return ErrUnavailable
		}
	case "darwin":
		backend = keyring.KeychainBackend
	case "windows":
		backend = keyring.WinCredBackend
	default:
		return ErrUnavailable
	}
	r, e := keyring.Open(keyring.Config{AllowedBackends: []keyring.BackendType{backend}, ServiceName: "provenance-cli", LibSecretCollectionName: collection, KeychainAccessibleWhenUnlocked: true, KeychainTrustApplication: false})
	if e != nil {
		return ErrUnavailable
	}
	n.ring = r
	return nil
}

// Native APIs can display an OS prompt. Bound caller lifetime without exposing
// backend errors/secret values. The command exits after timeout, never falls back.
func bounded(ctx context.Context, fn func() error) error {
	ch := make(chan error, 1)
	go func() { ch <- fn() }()
	select {
	case <-ctx.Done():
		return ErrUnavailable
	case e := <-ch:
		if e != nil {
			return ErrUnavailable
		}
		return nil
	}
}
func (n *Native) Ready(ctx context.Context) error {
	return bounded(ctx, func() error {
		n.mu.Lock()
		defer n.mu.Unlock()
		if ctx.Err() != nil {
			return ErrUnavailable
		}
		if e := n.open(); e != nil {
			return e
		}
		b := make([]byte, 16)
		if _, e := rand.Read(b); e != nil {
			return e
		}
		key := "probe/" + hex.EncodeToString(b)
		if e := n.ring.Set(keyring.Item{Key: key, Data: b, KeychainNotSynchronizable: true, KeychainNotTrustApplication: true}); e != nil {
			return e
		}
		item, e := n.ring.Get(key)
		removed := n.ring.Remove(key)
		if e != nil || removed != nil || string(item.Data) != string(b) {
			return ErrUnavailable
		}
		return nil
	})
}
func (n *Native) Get(ctx context.Context, origin, kind string) (string, error) {
	type result struct {
		value string
		err   error
	}
	ch := make(chan result, 1)
	go func() {
		n.mu.Lock()
		defer n.mu.Unlock()
		if ctx.Err() != nil || n.ring == nil || n.open() != nil {
			ch <- result{err: ErrUnavailable}
			return
		}
		item, e := n.ring.Get(origin + "/" + kind)
		ch <- result{string(item.Data), e}
	}()
	select {
	case <-ctx.Done():
		return "", ErrUnavailable
	case r := <-ch:
		if r.err != nil {
			return "", ErrUnavailable
		}
		return r.value, nil
	}
}
func (n *Native) Set(ctx context.Context, origin, kind, value string) error {
	return bounded(ctx, func() error {
		n.mu.Lock()
		defer n.mu.Unlock()
		if ctx.Err() != nil || n.ring == nil || n.open() != nil {
			return ErrUnavailable
		}
		return n.ring.Set(keyring.Item{Key: origin + "/" + kind, Data: []byte(value), KeychainNotSynchronizable: true, KeychainNotTrustApplication: true})
	})
}

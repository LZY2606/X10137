package memguard

import (
	"bytes"
	"sync"
	"testing"

	"github.com/awnumar/memguard/core"
)

// Zero-length buffers are "quasi-destroyed" null buffers: every operation
// must be a safe no-op and Seal must return a nil Enclave.
func TestLifecycleZeroLength(t *testing.T) {
	b := NewBuffer(0)
	if b == nil {
		t.Fatal("null buffer should not be nil")
	}
	if b.IsAlive() {
		t.Error("null buffer should not be alive")
	}
	if b.IsMutable() {
		t.Error("null buffer should be immutable")
	}
	if b.Size() != 0 {
		t.Error("null buffer should have size zero")
	}
	if b.Bytes() != nil {
		t.Error("null buffer should have a nil data slice")
	}
	if b.EqualTo([]byte("x")) {
		t.Error("destroyed buffer must never compare equal")
	}

	// Every mutating/querying operation must be a safe no-op.
	b.Freeze()
	b.Melt()
	b.Wipe()
	b.Scramble()
	b.Copy([]byte("x"))
	b.Move([]byte("x"))
	b.Destroy()
	b.Destroy()

	if e := b.Seal(); e != nil {
		t.Error("sealing a null buffer should return a nil enclave")
	}
	if e := NewEnclave([]byte{}); e != nil {
		t.Error("sealing empty data should return a nil enclave")
	}
}

// Destroy must be idempotent, including under concurrent invocation.
func TestLifecycleRepeatedDestroy(t *testing.T) {
	b := NewBuffer(32)
	if !b.IsAlive() {
		t.Fatal("buffer should be alive")
	}
	b.Destroy()
	if b.IsAlive() {
		t.Error("buffer should be destroyed")
	}
	if b.Size() != 0 || b.Bytes() != nil {
		t.Error("destroyed buffer should expose no data")
	}
	b.Destroy() // second destroy must be a no-op, not a panic

	c := NewBuffer(32)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.Destroy()
		}()
	}
	wg.Wait()
	if c.IsAlive() {
		t.Error("concurrently destroyed buffer should be dead")
	}
}

// Move wipes the source slice, and Seal consumes the LockedBuffer handle:
// the old handle is dead afterwards while the Enclave remains usable.
func TestLifecycleMoveAndOldHandle(t *testing.T) {
	src := []byte("yellow submarine")
	b := NewBuffer(len(src))
	b.Move(src)

	if !bytes.Equal(src, make([]byte, len(src))) {
		t.Error("source slice should be wiped after Move")
	}
	if !bytes.Equal(b.Bytes(), []byte("yellow submarine")) {
		t.Error("buffer should hold the moved data")
	}

	e := b.Seal()
	if e == nil {
		t.Fatal("seal should return an enclave")
	}
	if b.IsAlive() {
		t.Error("old handle should be dead after Seal")
	}
	if b.Size() != 0 {
		t.Error("old handle should have size zero after Seal")
	}

	// Operations on the old handle are no-ops and must not affect the enclave.
	b.Freeze()
	b.Melt()
	b.Destroy()

	opened, err := e.Open()
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	if !bytes.Equal(opened.Bytes(), []byte("yellow submarine")) {
		t.Error("opened data does not match original")
	}
	opened.Destroy()
}

// Freeze and Melt toggle the protection bits of the inner pages and are
// idempotent; the cycle can be repeated and data stays intact throughout.
func TestLifecycleFreezeMeltCycle(t *testing.T) {
	b := NewBuffer(16)
	for i := 0; i < 3; i++ {
		b.Freeze()
		if b.IsMutable() {
			t.Error("buffer should be immutable after Freeze")
		}
		b.Freeze() // idempotent
		if b.IsMutable() {
			t.Error("repeated Freeze changed state")
		}
		b.Melt()
		if !b.IsMutable() {
			t.Error("buffer should be mutable after Melt")
		}
		b.Melt() // idempotent
		if !b.IsMutable() {
			t.Error("repeated Melt changed state")
		}
	}

	// Writable after Melt, readable while Frozen.
	b.Copy([]byte("yellow submarine"))
	b.Freeze()
	if !b.EqualTo([]byte("yellow submarine")) {
		t.Error("data should be readable while frozen")
	}
	b.Melt()
	if !b.EqualTo([]byte("yellow submarine")) {
		t.Error("data should survive freeze/melt cycles")
	}

	b.Destroy()
	// Freeze/Melt on a destroyed buffer are no-ops.
	b.Freeze()
	b.Melt()
	if b.IsMutable() {
		t.Error("destroyed buffer must report immutable")
	}
}

// A corrupted enclave (here: session key invalidated by Purge, which makes
// authentication fail exactly as ciphertext tampering would) causes Open to
// return ErrDecryptionFailed and a nil buffer. The session must remain
// usable, and a later Purge must clean up temporary state without panicking.
func TestLifecycleCorruptedEnclave(t *testing.T) {
	e := NewEnclave([]byte("yellow submarine"))
	if e == nil {
		t.Fatal("got nil enclave")
	}
	if e.Size() != 16 {
		t.Error("enclave should report plaintext size of 16")
	}

	Purge() // resets the session key; existing enclaves become undecryptable

	b, err := e.Open()
	if err != core.ErrDecryptionFailed {
		t.Error("expected ErrDecryptionFailed, got:", err)
	}
	if b != nil {
		t.Error("failed Open must return a nil buffer")
	}

	// The session is still usable after a failed Open.
	fresh := NewBuffer(8)
	if !fresh.IsAlive() {
		t.Error("new buffers should work after a failed Open")
	}
	fresh.Destroy()

	e2 := NewEnclave([]byte("submarine"))
	opened, err := e2.Open()
	if err != nil {
		t.Error("new enclaves should open with the fresh key:", err)
	}
	if !bytes.Equal(opened.Bytes(), []byte("submarine")) {
		t.Error("opened data does not match")
	}
	opened.Destroy()

	// Global purge cleans up any temporary buffers left behind by the
	// failed Open above; it must complete without panicking.
	Purge()
}

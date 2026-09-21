package memguard

import (
	"bytes"
	"sync"
	"testing"

	"github.com/awnumar/memguard/core"
)

// Zero-length requests must yield a quasi-destroyed null buffer that is safe
// to inspect and destroy, and a nil Enclave.
func TestLifecycleZeroLength(t *testing.T) {
	b := NewBuffer(0)
	if b == nil {
		t.Fatal("NewBuffer(0) returned nil handle")
	}
	if b.Size() != 0 {
		t.Error("null buffer has non-zero size")
	}
	if b.IsAlive() {
		t.Error("null buffer reports itself alive")
	}
	if got := b.Bytes(); len(got) != 0 {
		t.Error("null buffer exposes a non-empty slice")
	}
	// Destroying a null buffer must be a safe no-op, even repeatedly.
	b.Destroy()
	b.Destroy()

	if e := NewEnclave([]byte{}); e != nil {
		t.Error("NewEnclave of empty input should return nil")
	}
	if nb := NewBufferFromBytes(nil); nb.Size() != 0 {
		t.Error("NewBufferFromBytes(nil) should yield a zero-size buffer")
	}
}

// Destroy must be idempotent and safe under concurrency: exactly one caller
// performs the teardown, the rest observe a no-op.
func TestLifecycleRepeatedAndConcurrentDestroy(t *testing.T) {
	b := NewBuffer(32)
	if !b.IsAlive() {
		t.Fatal("fresh buffer is not alive")
	}
	b.Destroy()
	if b.IsAlive() {
		t.Error("buffer still alive after Destroy")
	}
	if b.Size() != 0 {
		t.Error("destroyed buffer has non-zero size")
	}
	if got := b.Bytes(); got != nil {
		t.Error("destroyed buffer still exposes a data slice")
	}
	b.Destroy() // second destroy must not panic

	c := NewBuffer(64)
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
		t.Error("buffer alive after concurrent Destroy")
	}
}

// Move wipes the source, so a caller-held alias of the source observes zeros.
// Operations on a destroyed handle are no-ops and leave the source untouched.
func TestLifecycleMoveSemantics(t *testing.T) {
	src := []byte("yellow submarine")
	b := NewBuffer(16)
	b.Move(src)

	if !bytes.Equal(src, make([]byte, 16)) {
		t.Error("source not wiped after Move")
	}
	if !b.EqualTo([]byte("yellow submarine")) {
		t.Error("destination does not hold moved data")
	}
	b.Destroy()

	// Move into a destroyed buffer is a no-op: the source must be left as-is.
	dead := NewBuffer(8)
	dead.Destroy()
	kept := []byte("12345678")
	dead.Move(kept)
	if !bytes.Equal(kept, []byte("12345678")) {
		t.Error("Move on destroyed buffer should not touch the source")
	}
}

// Freeze and Melt toggle the mutability bit and the page protection in
// lockstep, are idempotent, and become no-ops after Destroy.
func TestLifecycleFreezeMeltCycle(t *testing.T) {
	b := NewBuffer(32)
	if !b.IsMutable() {
		t.Fatal("fresh buffer should be mutable")
	}
	for i := 0; i < 4; i++ {
		b.Freeze()
		b.Freeze() // idempotent
		if b.IsMutable() {
			t.Error("buffer still mutable after Freeze")
		}
		b.Melt()
		b.Melt() // idempotent
		if !b.IsMutable() {
			t.Error("buffer still immutable after Melt")
		}
	}

	// Data written while mutable must be readable after a Freeze/Melt cycle.
	payload := bytes.Repeat([]byte("abcd"), 8)
	b.Move(payload)
	b.Freeze()
	if !b.EqualTo(bytes.Repeat([]byte("abcd"), 8)) {
		t.Error("data corrupted across Freeze/Melt cycle")
	}
	b.Melt()
	b.Destroy()

	// Freeze/Melt on a destroyed buffer are safe no-ops.
	b.Freeze()
	b.Melt()
	if b.IsMutable() {
		t.Error("destroyed buffer reports mutable")
	}
}

// An Enclave whose session key is gone (here via Purge, which resets the key)
// fails authentication on Open: the error is returned, no buffer is handed
// out, and the process does not panic.
func TestLifecycleUndecryptableEnclave(t *testing.T) {
	e := NewEnclave([]byte("yellow submarine"))
	if e == nil {
		t.Fatal("got nil enclave")
	}

	// Sanity: it opens fine before the key is destroyed.
	b, err := e.Open()
	if err != nil {
		t.Fatal("unexpected open error:", err)
	}
	if !b.EqualTo([]byte("yellow submarine")) {
		t.Error("round-trip data mismatch")
	}
	b.Destroy()

	// Resetting the session key makes existing enclaves undecryptable.
	Purge()

	opened, err := e.Open()
	if err != core.ErrDecryptionFailed {
		t.Error("expected ErrDecryptionFailed, got:", err)
	}
	if opened != nil {
		t.Error("failed Open handed out a buffer")
	}
}

package audit_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/thomas666-beast/cryptkit/audit"
)

func testKey() []byte { return bytes.Repeat([]byte{0xA5}, 32) }

func TestAppendAndVerify(t *testing.T) {
	var buf bytes.Buffer
	l, err := audit.NewWriterLog(&buf, testKey())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		if err := l.Append(audit.Record{Op: audit.OpEncrypt, Bytes: int64(i)}); err != nil {
			t.Fatal(err)
		}
	}
	recs, err := audit.ReadAll(strings.NewReader(buf.String()))
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 10 {
		t.Fatalf("want 10 records, got %d", len(recs))
	}
	if err := audit.Verify(recs, testKey()); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestTamperDetected(t *testing.T) {
	var buf bytes.Buffer
	l, _ := audit.NewWriterLog(&buf, testKey())
	_ = l.Append(audit.Record{Op: audit.OpEncrypt, Bytes: 1})
	_ = l.Append(audit.Record{Op: audit.OpEncrypt, Bytes: 2})
	_ = l.Append(audit.Record{Op: audit.OpEncrypt, Bytes: 3})

	recs, _ := audit.ReadAll(strings.NewReader(buf.String()))
	recs[1].Bytes = 999 // tamper
	err := audit.Verify(recs, testKey())
	if err == nil {
		t.Fatal("expected tamper to be detected")
	}
	if !errors.Is(err, audit.ErrChainBroken) {
		t.Fatalf("want ErrChainBroken, got %v", err)
	}
}

func TestWrongKeyRejected(t *testing.T) {
	var buf bytes.Buffer
	l, _ := audit.NewWriterLog(&buf, testKey())
	_ = l.Append(audit.Record{Op: audit.OpEncrypt})

	recs, _ := audit.ReadAll(strings.NewReader(buf.String()))
	wrong := bytes.Repeat([]byte{0x00}, 32)
	if err := audit.Verify(recs, wrong); err == nil {
		t.Fatal("expected wrong key to fail verification")
	}
}

func TestResume(t *testing.T) {
	var buf bytes.Buffer
	l, _ := audit.NewWriterLog(&buf, testKey())
	_ = l.Append(audit.Record{Op: audit.OpEncrypt, Bytes: 1})
	_ = l.Append(audit.Record{Op: audit.OpEncrypt, Bytes: 2})

	// Reopen for append: read existing, continue with seq=2.
	var out bytes.Buffer
	l2, err := audit.OpenReaderLog(strings.NewReader(buf.String()), &out, testKey())
	if err != nil {
		t.Fatal(err)
	}
	if l2.Seq() != 2 {
		t.Fatalf("resume seq: want 2, got %d", l2.Seq())
	}
	if err := l2.Append(audit.Record{Op: audit.OpDecrypt, Bytes: 2}); err != nil {
		t.Fatal(err)
	}
	recs, _ := audit.ReadAll(strings.NewReader(out.String()))
	if len(recs) != 1 {
		t.Fatalf("want 1 new record, got %d", len(recs))
	}
	if recs[0].Seq != 2 {
		t.Fatalf("want seq=2, got %d", recs[0].Seq)
	}
}

func TestReadAllExported(t *testing.T) {
	// ensure ReadAll is exported (test calls it above)
	var buf bytes.Buffer
	l, _ := audit.NewWriterLog(&buf, testKey())
	_ = l.Append(audit.Record{Op: audit.OpEncrypt})
	if _, err := audit.ReadAll(strings.NewReader(buf.String())); err != nil {
		t.Fatal(err)
	}
}

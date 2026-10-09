package audit

import (
	"errors"
	"fmt"
)

// Verify walks the records and checks:
//   - seq is contiguous from 0
//   - each PrevHash matches the previous record's hash
//   - each Signature is valid under key
//
// Returns the index of the first bad record on failure.
func Verify(records []Record, key []byte) error {
	var prev string
	for i, r := range records {
		if r.Seq != uint64(i) {
			return fmt.Errorf("%w: record %d: seq=%d, want %d",
				ErrChainBroken, i, r.Seq, i)
		}
		if r.PrevHash != prev {
			return fmt.Errorf("%w: record %d: prev=%s, want %s",
				ErrChainBroken, i, r.PrevHash, prev)
		}
		if err := r.verify(key); err != nil {
			return fmt.Errorf("%w: record %d: %v", ErrChainBroken, i, err)
		}
		prev = r.hashRecord()
	}
	return nil
}

// ErrVerify wraps all verification failures.
var ErrVerify = errors.New("cryptkit/audit: verification failed")

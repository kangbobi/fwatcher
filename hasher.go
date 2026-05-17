package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
)

type Snapshot struct {
	Hash    string
	Size    int64
	Content []byte // nil for dirs, oversized files, or binary content
	Binary  bool
}

// ReadSnapshot returns hash + size + (optionally) content of a file in one read.
//
//	maxHashBytes    : files larger than this skip hashing entirely
//	                  (Hash = "skipped:too_large"). 0 = no limit.
//	maxContentBytes : files larger than this are still hashed (streaming)
//	                  but their content is NOT kept in memory. 0 = never keep content.
//
// Binary files (NUL in first 8 KiB) are hashed but content is dropped, and
// Binary=true is set so callers can avoid emitting a junk diff.
func ReadSnapshot(path string, maxHashBytes, maxContentBytes int64) (Snapshot, error) {
	f, err := os.Open(path)
	if err != nil {
		return Snapshot{}, err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return Snapshot{}, err
	}
	if st.IsDir() {
		return Snapshot{}, nil
	}

	snap := Snapshot{Size: st.Size()}

	if maxHashBytes > 0 && snap.Size > maxHashBytes {
		snap.Hash = "skipped:too_large"
		return snap, nil
	}

	// Too big to keep content — stream-hash only
	if maxContentBytes <= 0 || snap.Size > maxContentBytes {
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return snap, err
		}
		snap.Hash = "sha256:" + hex.EncodeToString(h.Sum(nil))
		return snap, nil
	}

	data, err := io.ReadAll(f)
	if err != nil {
		return snap, err
	}
	sum := sha256.Sum256(data)
	snap.Hash = "sha256:" + hex.EncodeToString(sum[:])

	probe := len(data)
	if probe > 8192 {
		probe = 8192
	}
	snap.Binary = bytes.IndexByte(data[:probe], 0) != -1

	if !snap.Binary {
		snap.Content = data
	}
	return snap, nil
}

// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package hash

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/amwolff/awsig"
)

// fakeAwsigReader mimics an awsig.Reader, whose checksums are only available
// after reading to EOF.
type fakeAwsigReader struct {
	r   *bytes.Reader
	eof bool
}

func (f *fakeAwsigReader) Read(p []byte) (int, error) {
	n, err := f.r.Read(p)
	if errors.Is(err, io.EOF) {
		f.eof = true
	}
	return n, err
}

func (f *fakeAwsigReader) Checksums() (map[awsig.ChecksumAlgorithm][]byte, error) {
	if !f.eof {
		return nil, errors.New("not at EOF")
	}
	return map[awsig.ChecksumAlgorithm][]byte{awsig.AlgorithmMD5: {1}}, nil
}

func TestAwsigReaderChecksumsWithoutEOF(t *testing.T) {
	// An empty body wrapped in a 0-byte reader is never read.
	r := NewAwsigReader(&fakeAwsigReader{r: bytes.NewReader(nil)}, 0, 0)
	sums, err := Wrap(bytes.NewReader(nil), r, 0, 0).Checksums()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sums[AlgorithmMD5], []byte{1}) {
		t.Fatalf("unexpected checksums %v", sums)
	}

	// Data beyond the declared size is an error.
	r = NewAwsigReader(&fakeAwsigReader{r: bytes.NewReader([]byte("x"))}, 0, 0)
	if _, err := r.Checksums(); err == nil {
		t.Fatal("expected error for data beyond declared size")
	}

	// Checksums are still unavailable before all declared bytes are read.
	r = NewAwsigReader(&fakeAwsigReader{r: bytes.NewReader([]byte("x"))}, 1, 1)
	if _, err := r.Checksums(); err == nil {
		t.Fatal("expected error before reading all data")
	}
}

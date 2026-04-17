// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package hash

import (
	"errors"
	"fmt"
	"io"

	"github.com/amwolff/awsig"
)

var (
	algorithmFromAwsig = map[awsig.ChecksumAlgorithm]Algorithm {
		awsig.AlgorithmCRC32:     AlgorithmCRC32,
		awsig.AlgorithmCRC32C:    AlgorithmCRC32C,
		awsig.AlgorithmCRC64NVME: AlgorithmCRC64NVME,
		awsig.AlgorithmMD5:       AlgorithmMD5,
		awsig.AlgorithmSHA1:      AlgorithmSHA1,
		awsig.AlgorithmSHA256:    AlgorithmSHA256,
	}

	algorithmToAwsig = invertMap(algorithmFromAwsig)
)

type awsigReader struct {
	reader     awsig.Reader
	size       int64
	actualSize int64
	getMD5     func() ([]byte, error)

	eof bool
}

// NewAwsigReader returns an implementation of Reader that exposes checksums computed by an awsig.Reader.
// Unlike the reader returned by NewDefaultReader, it performs no checksum verification of its own.
// The awsig.Reader is responsible for verifying checksums.
func NewAwsigReader(reader awsig.Reader, size, actualSize int64) Reader {
	return &awsigReader{
		reader:     reader,
		size:       size,
		actualSize: actualSize,
	}
}

// Read implements Reader.
func (r *awsigReader) Read(p []byte) (n int, err error) {
	n, err = r.reader.Read(p)
	if !r.eof && errors.Is(err, io.EOF) {
		r.eof = true
	}
	return n, err
}

// Size returns the absolute number of bytes the Reader will return during reading.
// It returns -1 for unlimited data.
func (reader *awsigReader) Size() int64 {
	return reader.size
}

// ActualSize returns the pre-modified size of the object.
func (reader *awsigReader) ActualSize() int64 {
	return reader.actualSize
}

// Checksums returns the checksums of the content. It must not be called until
// all data has been read (indicated by Read returning io.EOF).
func (reader *awsigReader) Checksums() (map[Algorithm][]byte, error) {
	if !reader.eof {
		return nil, errNoEarlyChecksums
	}

	awsigChecksums, err := reader.reader.Checksums()
	if err != nil {
		return nil, fmt.Errorf("error retrieving checksums from awsig reader: %w", err)
	}

	checksums := make(map[Algorithm][]byte)
	for awsigAlgo, checksum := range awsigChecksums {
		if algo, ok := algorithmFromAwsig[awsigAlgo]; ok {
			checksums[algo] = checksum
		}
	}

	return checksums, nil
}

// AlgorithmToAwsig translates an Algorithm into an awsig.ChecksumAlgorithm.
func AlgorithmToAwsig(algo Algorithm) (awsigAlgo awsig.ChecksumAlgorithm, ok bool) {
	awsigAlgo, ok = algorithmToAwsig[algo]
	return awsigAlgo, ok
}

func invertMap[K comparable, V comparable](m map[K]V) map[V]K {
	inverted := make(map[V]K)
	for K, V := range m {
		inverted[V] = K
	}
	return inverted
}

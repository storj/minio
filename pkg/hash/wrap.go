// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package hash

import (
	"io"
)

type wrappingReader struct {
	io.Reader
	hashReader Reader
	size       int64
	actualSize int64
}

// Wrap returns an implementation of Reader that wraps an io.Reader and exposes
// checksums computed by an underlying Reader. Unlike the reader returned by
// NewDefaultReader, it performs no checksum verification.
//
// The provided io.Reader should wrap the Reader. For example, the io.Reader
// may perform transformations such as compression to the data returned by its
// underlying Reader.
//
//   hashReader := NewDefaultReader(...)
//   // Create an io.Reader that transforms the data returned by the Reader.
//   compressionReader := Compress(hashReader)
//   // Create a Reader that reads and returns the transformed data and exposes
//   // the checksums of the original data computed by the underlying Reader.
//   compressionHashReader := Wrap(compressionReader, reader)
//
func Wrap(wrapped io.Reader, reader Reader, size, actualSize int64) Reader {
	if size >= 0 {
		wrapped = io.LimitReader(wrapped, size)
	}
	return &wrappingReader{
		Reader:     wrapped,
		hashReader: reader,
		size:       size,
		actualSize: actualSize,
	}
}

func (reader *wrappingReader) Size() int64 {
	return reader.size
}

func (reader *wrappingReader) ActualSize() int64 {
	return reader.actualSize
}

func (reader *wrappingReader) Checksums() (map[Algorithm][]byte, error) {
	return reader.hashReader.Checksums()
}

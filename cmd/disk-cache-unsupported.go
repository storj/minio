// Copyright (C) 2025 Storj Labs, Inc.
// See LICENSE for copying information.

package cmd

import (
	"context"
	"net/http"
)

// Ensure that cacheObjectLayerUnsupported implements CacheObjectLayer.
var _ CacheObjectLayer = (*cacheObjectLayerUnsupported)(nil)

// cacheObjectLayerUnsupported is a stub implementation of CacheObjectLayer.
type cacheObjectLayerUnsupported struct {}

func (c cacheObjectLayerUnsupported) GetObjectNInfo(ctx context.Context, bucket, object string, rs *HTTPRangeSpec, h http.Header, lockType LockType, opts ObjectOptions) (*GetObjectReader, error) {
	return nil, NotImplemented{}
}

func (c cacheObjectLayerUnsupported) GetObjectInfo(ctx context.Context, bucket, object string, opts ObjectOptions) (ObjectInfo, error) {
	return ObjectInfo{}, NotImplemented{}
}

func (c cacheObjectLayerUnsupported) DeleteObject(ctx context.Context, bucket, object string, opts ObjectOptions) (ObjectInfo, error) {
	return ObjectInfo{}, NotImplemented{}
}

func (c cacheObjectLayerUnsupported) DeleteObjects(ctx context.Context, bucket string, objects []ObjectToDelete, opts ObjectOptions) ([]DeletedObject, []DeleteObjectsError, error) {
	return nil, nil, NotImplemented{}
}

func (c cacheObjectLayerUnsupported) PutObject(ctx context.Context, bucket, object string, data *PutObjReader, opts ObjectOptions) (objInfo ObjectInfo, err error) {
	return ObjectInfo{}, NotImplemented{}
}

func (c cacheObjectLayerUnsupported) CopyObject(ctx context.Context, srcBucket, srcObject, destBucket, destObject string, srcInfo ObjectInfo, srcOpts, dstOpts ObjectOptions) (objInfo ObjectInfo, err error) {
	return ObjectInfo{}, NotImplemented{}
}

func (c cacheObjectLayerUnsupported) StorageInfo(ctx context.Context) CacheStorageInfo {
	return CacheStorageInfo{}
}

func (c cacheObjectLayerUnsupported) CacheStats() *CacheStats {
	return nil
}

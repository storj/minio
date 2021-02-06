package cmd

import (
	"github.com/storj/minio/cmd/rest"
	xnet "github.com/storj/minio/pkg/net"
)

func isNetworkError(err error) bool {
	if err == nil {
		return false
	}
	if nerr, ok := err.(*rest.NetworkError); ok {
		return xnet.IsNetworkOrHostDown(nerr.Err, false)
	}
	return false
}

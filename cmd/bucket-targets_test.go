// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package cmd

import (
	"context"
	"net/url"
	"reflect"
	"testing"

	miniogo "github.com/minio/minio-go/v7"

	xhttp "storj.io/minio/cmd/http"
	"storj.io/minio/pkg/bucket/replication"
)

func TestRemoteTargetTagEncoding(t *testing.T) {
	builders := map[string]func(ObjectInfo) (miniogo.PutObjectOptions, error){
		"transition": putTransitionOpts,
		"replication": func(oi ObjectInfo) (miniogo.PutObjectOptions, error) {
			return putReplicationOpts(context.Background(), replication.Destination{}, oi)
		},
	}
	for name, build := range builders {
		t.Run(name, func(t *testing.T) {
			for _, tc := range []struct {
				name    string
				tags    string
				wantErr bool
			}{
				{"empty", "", false},
				{"ascii", "owner=Jurgen&project=test", false},
				{"unicode value", "owner=J%C3%BCrgen", true},
				{"unicode key", "%C3%A9quipe=test", true},
				{"mixed", "owner=abc&project=%C3%A9t%C3%A9", true},
				{"punctuation", "owner=a%21b", true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					opts, err := build(ObjectInfo{UserTags: tc.tags})
					if (err != nil) != tc.wantErr {
						t.Fatalf("error = %v, want error = %v", err, tc.wantErr)
					}
					if err != nil {
						return
					}
					got, err := url.ParseQuery(opts.Header().Get(xhttp.AmzObjectTagging))
					if err != nil {
						t.Fatal(err)
					}
					want, _ := url.ParseQuery(tc.tags)
					if !reflect.DeepEqual(got, want) {
						t.Fatalf("outgoing tags = %v, want %v", got, want)
					}
				})
			}
		})
	}
}

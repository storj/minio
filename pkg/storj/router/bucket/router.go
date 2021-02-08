package bucket

import (
	"net/http"

	"github.com/gorilla/mux"

	"github.com/storj/minio/pkg/storj/router"
	"github.com/storj/minio/pkg/storj/router/object"
)

// Attach adds the bucket routes.
func Attach(domain string, r *mux.Router, h router.Handler) {
	root := r.Host(domain).Subrouter()

	pathStyle := root.PathPrefix("/{bucket:.+}").Subrouter()
	virtualHostStyle := r.Host("{bucket:.+}." + domain).Subrouter()

	for _, s := range []*mux.Router{pathStyle, virtualHostStyle} {
		object.Attach(s, h)

		if handler := h.Get(router.CreateBucket); handler != nil {
			s.Methods(http.MethodPut).HandlerFunc(handler)
		}
		if handler := h.Get(router.HeadBucket); handler != nil {
			s.Methods(http.MethodHead).HandlerFunc(handler)
		}
		if handler := h.Get(router.DeleteBucket); handler != nil {
			s.Methods(http.MethodDelete).HandlerFunc(handler)
		}
	}

	if handler := h.Get(router.ListBuckets); handler != nil {
		root.Methods(http.MethodGet).HandlerFunc(handler)
	}
}

package object

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/storj/minio/pkg/storj/router"
)

// Attach addes the object routes.
func Attach(r *mux.Router, h router.Handler) {
	o := r.Path("/{key:.+}").Subrouter()

	if handler := h.Get(router.PutObject); handler != nil {
		o.Methods(http.MethodPut).HandlerFunc(handler)
	}
	if handler := h.Get(router.HeadObject); handler != nil {
		o.Methods(http.MethodHead).HandlerFunc(handler)
	}
	if handler := h.Get(router.GetObject); handler != nil {
		o.Methods(http.MethodGet).HandlerFunc(handler)
	}
	if handler := h.Get(router.DeleteObject); handler != nil {
		o.Methods(http.MethodDelete).HandlerFunc(handler)
	}

	if handler := h.Get(router.ListObjectsV2); handler != nil {
		r.Methods(http.MethodGet).Queries("list-type", "2").HandlerFunc(handler)
	}
	if handler := h.Get(router.ListObjects); handler != nil {
		r.Methods(http.MethodGet).HandlerFunc(handler)
	}
}

package model

import (
	"encoding/xml"
	"log"
	"net/http"
)

// TODO: Figure out if zeebo/errs can help here...

// Error model
type Error struct {
	Err    error
	Status int
}

func (e *Error) Error() string {
	return e.Err.Error()
}

// ErrorResponse model
type ErrorResponse struct {
	XMLName    xml.Name `xml:"Error" json:"-"`
	Code       string
	Message    string
	Key        string `xml:"Key,omitempty" json:"Key,omitempty"`
	BucketName string `xml:"BucketName,omitempty" json:"BucketName,omitempty"`
	Resource   string
	Region     string `xml:"Region,omitempty" json:"Region,omitempty"`
	RequestID  string `xml:"RequestId" json:"RequestId"`
	HostID     string `xml:"HostId" json:"HostId"`
}

// ErrorResponser is an error that can be converted to an error response.
type ErrorResponser interface {
	ToErrorResponse() *ErrorResponse
}

func (e Error) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Println("ERROR", e)

	status := 500
	if e.Status != 0 {
		status = e.Status
	}

	w.WriteHeader(status)

	// FIXME: negotiate content type
	mimeType := ""

	body, err := Encode(mimeType, e.Err)
	if err != nil {
		return
	}

	w.Write(body)
}

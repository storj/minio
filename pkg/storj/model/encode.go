package model

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
)

// TODO: Lift the mimeType type from cmd/api-response.go
func Encode(mimeType string, payload interface{}) ([]byte, error) {
	switch mimeType {
	case "application/xml":
		return encodeXML(payload)
	case "application/json":
		return encodeJSON(payload)
	default:
		return encodeXML(payload)
	}
}

func encodeXML(payload interface{}) ([]byte, error) {
	// TODO: Look for better encoders.
	var bytesBuffer bytes.Buffer

	bytesBuffer.WriteString(xml.Header)
	e := xml.NewEncoder(&bytesBuffer)
	err := e.Encode(payload)
	return bytesBuffer.Bytes(), err
}

func encodeJSON(payload interface{}) ([]byte, error) {
	// TODO: Look for better encoders.
	var bytesBuffer bytes.Buffer

	e := json.NewEncoder(&bytesBuffer)
	err := e.Encode(payload)

	return bytesBuffer.Bytes(), err
}

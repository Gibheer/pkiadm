package pkiadm

import (
	"fmt"
)

// Result is a struct to send error messages from the server to the client.
type Result struct {
	// TODO make field private to avoid accidental write
	// HasError is true when an error was hit
	HasError bool
	// Error contains a list of errors, which can be used to add more details.
	Error Error
	// A message with more detailed information can be provided.
	Message string
}

type Error string

func (e Error) Error() string { return string(e) }
func (r *Result) SetError(err error, msg string, args ...interface{}) {
	r.HasError = true
	r.Error = Error(err.Error())
	if len(args) > 0 {
		r.Message = fmt.Sprintf(msg, args)
	} else {
		r.Message = msg
	}
}

// TODO documentation and cleanup
const (
	RTPrivateKey ResourceType = iota
	RTPublicKey
	RTCSR
	RTCertificate
	RTLocation
	RTSerial
	RTSubject
)

type ResourceName struct {
	ID   string
	Type ResourceType
}
type ResourceType uint

func (r ResourceName) String() string { return r.Type.String() + "/" + r.ID }

type Filter struct{}

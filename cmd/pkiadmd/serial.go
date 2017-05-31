package main

import (
	"crypto/rand"
	"math/big"

	"github.com/gibheer/pkiadm"
)

const (
	ELengthTooSmall = Error("Length must not be smaller than 1")
)

type (
	Serial struct {
		ID      string
		Min     int64
		Max     int64
		UsedIDs map[int64]bool
	}
)

// NewSerial generates a new serial generator.
func NewSerial(id string, min, max int64) (*Serial, error) {
	if max-min < 1 {
		return nil, ELengthTooSmall
	}
	// TODO check maximum length for certificate serial
	return &Serial{ID: id, Min: min, Max: max, UsedIDs: map[int64]bool{}}, nil
}

// Return the unique ResourceName
func (s *Serial) Name() pkiadm.ResourceName { return pkiadm.ResourceName{s.ID, pkiadm.RTSerial} }

// AddDependency registers a depending resource to be retuened by Dependencies()
// Refresh must trigger a rebuild of the resource.
func (s *Serial) Refresh(*Storage) error {
	// This is a NOOP, because there is nothing to refresh. Depending resources
	// pull their new ID themselves.
	return nil
}

// Return the PEM output of the contained resource.
func (s *Serial) Pem() ([]byte, error) { return []byte{}, nil }
func (s *Serial) Checksum() []byte     { return []byte{} }

// DependsOn must return the resource names it is depending on.
func (s *Serial) DependsOn() []pkiadm.ResourceName { return []pkiadm.ResourceName{} }

// Generate generates a new serial number and stores it to avoid double
// assigning.
func (s *Serial) Generate() (*big.Int, error) {
	val, err := rand.Int(rand.Reader, big.NewInt(s.Max-s.Min))
	if err != nil {
		return big.NewInt(-1), err
	}
	return big.NewInt(val.Int64() + s.Min), nil
}

package main

import (
	"crypto/rand"
	"fmt"
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

// Refresh must trigger a rebuild of the resource.
func (s *Serial) Refresh(*Storage) error {
	// This is a NOOP, because there is nothing to refresh. Depending resources
	// pull their new ID themselves.
	return nil
}

// RefreshInterval is a NOOP here, as serials can't be refreshed.
func (s *Serial) RefreshInterval() Interval {
	return NoInterval
}

// Return the PEM output of the contained resource.
func (s *Serial) Pem() ([]byte, error) { return []byte{}, nil }
func (s *Serial) Checksum() []byte     { return []byte{} }

// DependsOn must return the resource names it is depending on.
func (s *Serial) DependsOn() []pkiadm.ResourceName { return []pkiadm.ResourceName{} }

// Generate generates a new serial number and stores it to avoid double
// assigning.
func (s *Serial) Generate() (*big.Int, error) {
	for {
		val, err := rand.Int(rand.Reader, big.NewInt(s.Max-s.Min))
		if err != nil {
			return big.NewInt(-1), err
		}
		if _, found := s.UsedIDs[val.Int64()]; !found {
			s.UsedIDs[val.Int64()] = true
			return big.NewInt(val.Int64() + s.Min), nil
		}
	}
}

func (s *Server) CreateSerial(inSer pkiadm.Serial, res *pkiadm.Result) error {
	s.lock()
	defer s.unlock()

	ser, err := NewSerial(inSer.ID, inSer.Min, inSer.Max)
	if err != nil {
		res.SetError(err, "Could not create new serial '%s'", inSer.ID)
		return nil
	}
	if err := s.storage.AddSerial(ser); err != nil {
		res.SetError(err, "Could not add serial '%s'", inSer.ID)
		return nil
	}
	return s.store(res)
}
func (s *Server) SetSerial(changeset pkiadm.SerialChange, res *pkiadm.Result) error {
	s.lock()
	defer s.unlock()

	ser, err := s.storage.GetSerial(pkiadm.ResourceName{ID: changeset.Serial.ID, Type: pkiadm.RTSerial})
	if err != nil {
		res.SetError(err, "Could not find serial '%s'", changeset.Serial.ID)
		return nil
	}

	for _, field := range changeset.FieldList {
		switch field {
		case "min":
			ser.Min = changeset.Serial.Min
		case "max":
			ser.Max = changeset.Serial.Max
		default:
			res.SetError(fmt.Errorf("unknown field"), "unknown field '%s'", field)
			return nil
		}
	}
	if err := s.storage.Update(pkiadm.ResourceName{ID: ser.ID, Type: pkiadm.RTSerial}); err != nil {
		res.SetError(err, "Could not update serial '%s'", changeset.Serial.ID)
		return nil
	}
	return s.store(res)
}
func (s *Server) DeleteSerial(inSer pkiadm.ResourceName, res *pkiadm.Result) error {
	s.lock()
	defer s.unlock()

	ser, err := s.storage.GetSerial(pkiadm.ResourceName{ID: inSer.ID, Type: pkiadm.RTSerial})
	if err != nil {
		res.SetError(err, "Could not find serial '%s'", inSer.ID)
		return nil
	}

	if err := s.storage.Remove(ser); err != nil {
		res.SetError(err, "Could not remove serial '%s'", ser.ID)
		return nil
	}
	return s.store(res)
}
func (s *Server) ShowSerial(inSer pkiadm.ResourceName, res *pkiadm.ResultSerial) error {
	s.lock()
	defer s.unlock()

	ser, err := s.storage.GetSerial(pkiadm.ResourceName{ID: inSer.ID, Type: pkiadm.RTSerial})
	if err != nil {
		res.Result.SetError(err, "Could not find serial '%s'", inSer.ID)
		return nil
	}
	res.Serials = []pkiadm.Serial{pkiadm.Serial{
		ID:  ser.ID,
		Min: ser.Min,
		Max: ser.Max,
	}}
	return nil
}
func (s *Server) ListSerial(filter pkiadm.Filter, res *pkiadm.ResultSerial) error {
	s.lock()
	defer s.unlock()

	for _, ser := range s.storage.Serials {
		res.Serials = append(res.Serials, pkiadm.Serial{
			ID:  ser.ID,
			Min: ser.Min,
			Max: ser.Max,
		})
	}
	return nil
}

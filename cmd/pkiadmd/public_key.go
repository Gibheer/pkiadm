package main

import (
	"encoding/pem"
	"fmt"
	"time"

	"github.com/gibheer/pkiadm"
)

type (
	PublicKey struct {
		ID string

		PrivateKey pkiadm.ResourceName
		Type       pkiadm.PrivateKeyType // mark the type of the public key
		Key        []byte

		Interval Interval
	}
)

func NewPublicKey(id string, pk pkiadm.ResourceName, refreshAfter time.Duration,
	invalidAfter time.Duration) (*PublicKey, error) {
	pub := PublicKey{
		ID:         id,
		PrivateKey: pk,
		Interval: Interval{
			Created:      time.Now(),
			RefreshAfter: refreshAfter,
			InvalidAfter: invalidAfter,
		},
	}
	return &pub, nil
}

func (p *PublicKey) Name() pkiadm.ResourceName {
	return pkiadm.ResourceName{p.ID, pkiadm.RTPublicKey}
}

func (p *PublicKey) Refresh(lookup *Storage) error {
	pk, err := lookup.GetPrivateKey(p.PrivateKey)
	if err != nil {
		return err
	}
	p.Type = pk.PKType
	privateKey, err := pk.GetKey()
	if err != nil {
		return err
	}
	pubKey := privateKey.Public()
	block, err := pubKey.ToPem()
	if err != nil {
		return err
	}
	p.Key = pem.EncodeToMemory(&block)
	p.Interval.LastRefresh = time.Now()
	return nil
}

func (p *PublicKey) RefreshInterval() Interval {
	return p.Interval
}

func (p *PublicKey) DependsOn() []pkiadm.ResourceName {
	return []pkiadm.ResourceName{p.PrivateKey}
}

func (p *PublicKey) Pem() ([]byte, error) {
	return p.Key, nil
}

func (p *PublicKey) Checksum() []byte {
	return Hash(p.Key)
}

func (s *Server) CreatePublicKey(inPub pkiadm.PublicKey, res *pkiadm.Result) error {
	s.lock()
	defer s.unlock()

	pub, err := NewPublicKey(inPub.ID, inPub.PrivateKey, 0, 0)
	if err != nil {
		res.SetError(err, "Could not create public key '%s'", inPub.ID)
		return nil
	}
	if err := s.storage.AddPublicKey(pub); err != nil {
		res.SetError(err, "Could not add new public key '%s'", inPub.ID)
		return nil
	}
	return s.store(res)
}
func (s *Server) SetPublicKey(inPub pkiadm.PublicKeyChange, res *pkiadm.Result) error {
	s.lock()
	defer s.unlock()

	pub, err := s.storage.GetPublicKey(pkiadm.ResourceName{
		inPub.PublicKey.ID,
		pkiadm.RTPublicKey,
	})
	if err != nil {
		res.SetError(err, "Could not find public key '%s'", inPub.PublicKey.ID)
		return nil
	}
	for _, field := range inPub.FieldList {
		switch field {
		case "private-key":
			pub.PrivateKey = pkiadm.ResourceName{
				inPub.PublicKey.ID,
				pkiadm.RTPrivateKey,
			}
		default:
			res.SetError(fmt.Errorf("unknown field"), "unknown field '%s'", field)
		}
	}
	if err := s.storage.Update(pub.Name()); err != nil {
		res.SetError(err, "Could not update new public key '%s'", inPub.PublicKey.ID)
		return nil
	}
	return s.store(res)
}
func (s *Server) DeletePublicKey(inPub pkiadm.PublicKey, res *pkiadm.Result) error {
	s.lock()
	defer s.unlock()

	pub, err := s.storage.GetPublicKey(pkiadm.ResourceName{
		inPub.ID,
		pkiadm.RTPublicKey,
	})
	if err != nil {
		res.SetError(err, "Could not find public key '%s'", inPub.ID)
		return nil
	}
	if err := s.storage.Remove(pub); err != nil {
		res.SetError(err, "Could not remove public key '%s'", inPub.ID)
		return nil
	}
	return s.store(res)
}
func (s *Server) ShowPublicKey(inPub pkiadm.ResourceName, res *pkiadm.ResultPublicKey) error {
	s.lock()
	defer s.unlock()

	pub, err := s.storage.GetPublicKey(inPub)
	if err != nil {
		res.Result.SetError(err, "Could not find public key '%s'", inPub.ID)
		return nil
	}
	res.PublicKeys = []pkiadm.PublicKey{
		pkiadm.PublicKey{
			ID:         pub.ID,
			PrivateKey: pub.PrivateKey,
			Type:       pub.Type,
			Checksum:   pub.Checksum(),
		},
	}
	return nil
}
func (s *Server) ListPublicKey(filter pkiadm.Filter, res *pkiadm.ResultPublicKey) error {
	s.lock()
	defer s.unlock()

	for _, pub := range s.storage.PublicKeys {
		res.PublicKeys = append(res.PublicKeys, pkiadm.PublicKey{
			ID:         pub.ID,
			PrivateKey: pub.PrivateKey,
			Type:       pub.Type,
			Checksum:   pub.Checksum(),
		})
	}
	return nil
}

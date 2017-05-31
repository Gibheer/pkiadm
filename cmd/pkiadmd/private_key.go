package main

import (
	"crypto/elliptic"
	"encoding/pem"
	"fmt"

	"github.com/gibheer/pki"
	"github.com/gibheer/pkiadm"
)

const (
	EWrongKeyLength        = Error("key length for ecdsa must be one of 224, 256, 384 or 521")
	ELengthOutOfBounds     = Error("key length must be between 1024 and 32768")
	EWrongKeyLengthED25519 = Error("ed25519 keys only support 256 length")
)

type (
	PrivateKey struct {
		ID     string
		PKType pkiadm.PrivateKeyType
		Bits   uint
		Key    []byte
	}
)

func NewPrivateKey(id string, pkType pkiadm.PrivateKeyType, bits uint) (*PrivateKey, error) {
	if id == "" {
		return nil, ENoIDGiven
	}
	if err := verifyPK(pkType, bits); err != nil {
		return nil, err
	}
	pk := PrivateKey{
		ID:     id,
		PKType: pkType,
		Bits:   bits,
	}
	return &pk, nil
}

func (p *PrivateKey) Name() pkiadm.ResourceName {
	return pkiadm.ResourceName{p.ID, pkiadm.RTPrivateKey}
}

func (p *PrivateKey) Checksum() []byte {
	return Hash(p.Key)
}

func (p *PrivateKey) Pem() ([]byte, error) {
	return p.Key, nil
}

func (p *PrivateKey) DependsOn() []pkiadm.ResourceName {
	return []pkiadm.ResourceName{}
}

func (p *PrivateKey) Refresh(_ *Storage) error {
	var (
		key pki.PrivateKey
		err error
	)
	switch p.PKType {
	case pkiadm.PKTRSA:
		key, err = pki.NewPrivateKeyRsa(int(p.Bits))
	case pkiadm.PKTED25519:
		key, err = pki.NewPrivateKeyEd25519()
	case pkiadm.PKTECDSA:
		var curve elliptic.Curve
		switch p.Bits {
		case 224:
			curve = elliptic.P224()
		case 256:
			curve = elliptic.P256()
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		}
		key, err = pki.NewPrivateKeyEcdsa(curve)
	}
	if err != nil {
		return err
	}
	// set pem into the dump
	block, err := key.ToPem()
	if err != nil {
		return err
	}
	block.Headers = map[string]string{"ID": p.ID}
	p.Key = pem.EncodeToMemory(&block)
	return nil
}

func (p *PrivateKey) GetKey() (pki.PrivateKey, error) {
	var (
		err error
		key pki.PrivateKey
	)
	block, _ := pem.Decode(p.Key)
	switch block.Type {
	case pki.PemLabelRsa:
		key, err = pki.LoadPrivateKeyRsa(block.Bytes)
	case pki.PemLabelEd25519:
		key, err = pki.LoadPrivateKeyEd25519(block.Bytes)
	case pki.PemLabelEcdsa:
		key, err = pki.LoadPrivateKeyEcdsa(block.Bytes)
	default:
		return nil, fmt.Errorf("unknown private key type: %s - database corrupted", block.Type)
	}
	if err != nil {
		return nil, err
	}
	return key, nil
}

func verifyPK(pkType pkiadm.PrivateKeyType, bits uint) error {
	switch pkType {
	case pkiadm.PKTRSA:
		if bits < 1024 || bits > 32768 {
			return ELengthOutOfBounds
		}
	case pkiadm.PKTECDSA:
		switch bits {
		case 224, 256, 384, 521:
		default:
			return EWrongKeyLength
		}
	case pkiadm.PKTED25519:
		if bits != 256 {
			return EWrongKeyLengthED25519
		}
	default:
		return EUnknownType
	}
	return nil
}

func (s *Server) CreatePrivateKey(inPk pkiadm.PrivateKey, res *pkiadm.Result) error {
	s.lock()
	defer s.unlock()

	pk, err := NewPrivateKey(inPk.ID, inPk.Type, inPk.Bits)
	if err != nil {
		res.SetError(err, "Could not create new private key '%s'", inPk.ID)
		return nil
	}
	if err := s.storage.AddPrivateKey(pk); err != nil {
		res.SetError(err, "Could not add private key '%s'", inPk.ID)
		return nil
	}
	return s.store(res)
}
func (s *Server) SetPrivateKey(changeset pkiadm.PrivateKeyChange, res *pkiadm.Result) error {
	s.lock()
	defer s.unlock()

	pk, err := s.storage.GetPrivateKey(pkiadm.ResourceName{ID: changeset.PrivateKey.ID, Type: pkiadm.RTPrivateKey})
	if err != nil {
		res.SetError(err, "Could not find private key '%s'", changeset.PrivateKey.ID)
		return nil
	}

	for _, field := range changeset.FieldList {
		switch field {
		case "type":
			pk.PKType = changeset.PrivateKey.Type
		case "bits":
			pk.Bits = changeset.PrivateKey.Bits
		default:
			res.SetError(fmt.Errorf("unknown field"), "unknown field '%s'", field)
			return nil
		}
	}
	if err := s.storage.Update(pkiadm.ResourceName{ID: pk.ID, Type: pkiadm.RTPrivateKey}); err != nil {
		res.SetError(err, "Could not update private key '%s'", changeset.PrivateKey.ID)
		return nil
	}
	return s.store(res)
}
func (s *Server) DeletePrivateKey(inPk pkiadm.ResourceName, res *pkiadm.Result) error {
	s.lock()
	defer s.unlock()

	pk, err := s.storage.GetPrivateKey(pkiadm.ResourceName{ID: inPk.ID, Type: pkiadm.RTPrivateKey})
	if err != nil {
		res.SetError(err, "Could not find private key '%s'", inPk.ID)
		return nil
	}

	if err := s.storage.Remove(pk); err != nil {
		res.SetError(err, "Could not remove private key '%s'", pk.ID)
		return nil
	}
	return s.store(res)
}
func (s *Server) ShowPrivateKey(inPk pkiadm.ResourceName, res *pkiadm.ResultPrivateKey) error {
	s.lock()
	defer s.unlock()

	pk, err := s.storage.GetPrivateKey(pkiadm.ResourceName{ID: inPk.ID, Type: pkiadm.RTPrivateKey})
	if err != nil {
		res.Result.SetError(err, "Could not find private key '%s'", inPk.ID)
		return nil
	}
	res.PrivateKeys = []pkiadm.PrivateKey{pkiadm.PrivateKey{
		ID:       pk.ID,
		Type:     pk.PKType,
		Bits:     pk.Bits,
		Checksum: pk.Checksum(),
	}}
	return nil
}
func (s *Server) ListPrivateKey(filter pkiadm.Filter, res *pkiadm.ResultPrivateKey) error {
	s.lock()
	defer s.unlock()

	for _, pk := range s.storage.PrivateKeys {
		res.PrivateKeys = append(res.PrivateKeys, pkiadm.PrivateKey{
			ID:       pk.ID,
			Type:     pk.PKType,
			Bits:     pk.Bits,
			Checksum: pk.Checksum(),
		})
	}
	return nil
}

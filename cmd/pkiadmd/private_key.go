package main

import (
	"crypto/elliptic"
	"encoding/pem"
	"fmt"

	"github.com/gibheer/pki"
)

const (
	PKTRSA PrivateKeyType = iota
	PKTECDSA
	PKTED25519
)

const (
	EWrongKeyLength        = Error("key length for ecdsa must be one of 224, 256, 384 or 521")
	ELengthOutOfBounds     = Error("key length must be between 1024 and 32768")
	EWrongKeyLengthED25519 = Error("ed25519 keys only support 256 length")
)

type (
	PrivateKey struct {
		ID     string
		PKType PrivateKeyType
		Length uint
		Key    []byte
	}
	PrivateKeyType uint
)

func NewPrivateKey(id string, pkType PrivateKeyType, length uint) (*PrivateKey, error) {
	if id == "" {
		return nil, ENoIDGiven
	}
	if err := verifyPK(pkType, length); err != nil {
		return nil, err
	}
	pk := PrivateKey{
		ID:     id,
		PKType: pkType,
		Length: length,
	}
	return &pk, nil
}

func (p *PrivateKey) Name() ResourceName {
	return ResourceName{p.ID, RTPrivateKey}
}

func (p *PrivateKey) Checksum() []byte {
	return Hash(p.Key)
}

func (p *PrivateKey) Pem() ([]byte, error) {
	return p.Key, nil
}

func (p *PrivateKey) DependsOn() []ResourceName {
	return []ResourceName{}
}

func (p *PrivateKey) Refresh(_ *Storage) error {
	var (
		key pki.PrivateKey
		err error
	)
	switch p.PKType {
	case PKTRSA:
		key, err = pki.NewPrivateKeyRsa(int(p.Length))
	case PKTED25519:
		key, err = pki.NewPrivateKeyEd25519()
	case PKTECDSA:
		var curve elliptic.Curve
		switch p.Length {
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

func verifyPK(pkType PrivateKeyType, length uint) error {
	switch pkType {
	case PKTRSA:
		if length < 1024 || length > 32768 {
			return ELengthOutOfBounds
		}
	case PKTECDSA:
		switch length {
		case 224, 256, 384, 521:
		default:
			return EWrongKeyLength
		}
	case PKTED25519:
		if length != 256 {
			return EWrongKeyLengthED25519
		}
	default:
		return EUnknownType
	}
	return nil
}

//func (p *PrivateKey) MarshalJSON() ([]byte, error) {
//	return json.Marshal(*p)
//}
//func (p *PrivateKey) UnmarshalJSON(raw []byte) error {
//	return json.Unmarshal(raw, p)
//}

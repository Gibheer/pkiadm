package main

import (
	"encoding/pem"

	"github.com/gibheer/pkiadm"
)

const (
	PUTRSA PublicKeyType = iota
	PUTECDSA
	PUTED25519
)

type (
	PublicKey struct {
		ID string

		PrivateKey pkiadm.ResourceName
		Type       PublicKeyType // mark the type of the public key
		Key        []byte
	}

	PublicKeyType uint
)

func NewPublicKey(id string, pk pkiadm.ResourceName) (*PublicKey, error) {
	pub := PublicKey{
		ID:         id,
		PrivateKey: pk,
	}
	return &pub, nil
}

func (p *PublicKey) Name() pkiadm.ResourceName {
	return pkiadm.ResourceName{p.ID, pkiadm.RTPublicKey}
}

func (p *PublicKey) Refresh(lookup *Storage) error {
	r, err := lookup.Get(p.PrivateKey)
	if err != nil {
		return err
	}
	pk, ok := r.(*PrivateKey)
	if !ok {
		return EUnknownType
	}
	privateKey, err := pk.GetKey()
	if err != nil {
		return err
	}
	pubKey := privateKey.Public()
	block, err := pubKey.ToPem()
	if err != nil {
		return err
	}
	block.Headers = map[string]string{"ID": p.ID, "TYPE": p.Type.String()}
	p.Key = pem.EncodeToMemory(&block)
	return nil
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

//func (p *PublicKey) MarshalJSON() ([]byte, error) {
//	return json.Marshal(*p)
//}
//func (p *PublicKey) UnmarshalJSON(raw []byte) error {
//	return json.Unmarshal(raw, p)
//}

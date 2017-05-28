package main

import (
	"encoding/pem"
	"time"

	"github.com/gibheer/pki"
)

type (
	Certificate struct {
		ID string

		IsCA     bool
		Duration time.Duration

		PrivateKey ResourceName
		Serial     ResourceName
		CSR        ResourceName
		CA         ResourceName

		Data []byte
	}
)

func NewCertificate(id string, privateKey, serial, csr, ca ResourceName, isCA bool, duration time.Duration) (*Certificate, error) {
	return &Certificate{
		ID:         id,
		PrivateKey: privateKey,
		Serial:     serial,
		CSR:        csr,
		CA:         ca,
		IsCA:       isCA,
		Duration:   duration,
	}, nil
}

// Return the unique ResourceName
func (c *Certificate) Name() ResourceName {
	return ResourceName{c.ID, RTCertificate}
}

// AddDependency registers a depending resource to be retuened by Dependencies()
// Refresh must trigger a rebuild of the resource.
func (c *Certificate) Refresh(lookup *Storage) error {
	var ca *pki.Certificate
	if !c.IsCA {
		cert, err := lookup.GetCertificate(c.CA)
		if err != nil {
			return err
		}
		ca, err = cert.GetCertificate()
		if err != nil {
			return err
		}
	}
	csrRes, err := lookup.GetCSR(c.CSR)
	if err != nil {
		return err
	}
	csr, err := csrRes.GetCSR()
	if err != nil {
		return err
	}
	pkRes, err := lookup.GetPrivateKey(c.PrivateKey)
	if err != nil {
		return err
	}
	pk, err := pkRes.GetKey()
	if err != nil {
		return err
	}
	serRes, err := lookup.GetSerial(c.Serial)
	if err != nil {
		return err
	}
	serial, err := serRes.Generate()
	if err != nil {
		return err
	}

	// now we can start with the real interesting stuff
	// TODO add key usage and that stuff
	opts := pki.CertificateOptions{
		SerialNumber: serial,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(c.Duration),
		IsCA:         c.IsCA,
		CALength:     0, // TODO make this an option
	}
	cert, err := csr.ToCertificate(pk, opts, ca)
	if err != nil {
		return err
	}
	block, err := cert.ToPem()
	if err != nil {
		return err
	}
	block.Headers = map[string]string{"ID": c.ID}
	c.Data = pem.EncodeToMemory(&block)
	return nil
}

func (c *Certificate) GetCertificate() (*pki.Certificate, error) {
	// TODO fix this, we must check if there is anything else
	block, _ := pem.Decode(c.Data)
	cert, err := pki.LoadCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

// Return the PEM output of the contained resource.
func (c *Certificate) Pem() ([]byte, error) { return c.Data, nil }
func (c *Certificate) Checksum() []byte     { return Hash(c.Data) }

// DependsOn must return the resource names it is depending on.
func (c *Certificate) DependsOn() []ResourceName {
	res := []ResourceName{
		c.PrivateKey,
		c.Serial,
		c.CSR,
	}
	if !c.IsCA {
		res = append(res, c.CA)
	}
	return res
}

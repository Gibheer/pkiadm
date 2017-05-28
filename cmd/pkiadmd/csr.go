package main

import (
	"encoding/pem"
	"net"

	"github.com/gibheer/pki"
)

type (
	CSR struct {
		// ID is the unique identifier of the CSR.
		ID string

		// The following options are used to generate the content of the CSR.
		CommonName     string
		DNSNames       []string
		EmailAddresses []string
		IPAddresses    []net.IP

		// PrivateKey is needed to sign the certificate sign request.
		PrivateKey ResourceName
		Subject    ResourceName

		// Data contains the pem representation of the CSR.
		Data []byte
	}
)

// NewCSR creates a new CSR.
func NewCSR(id string, pk, subject ResourceName, commonName string, dnsNames []string,
	emailAddresses []string, iPAddresses []net.IP) (*CSR, error) {
	return &CSR{
		ID:             id,
		Subject:        subject,
		CommonName:     commonName,
		DNSNames:       dnsNames,
		EmailAddresses: emailAddresses,
		IPAddresses:    iPAddresses,
		PrivateKey:     pk,
	}, nil
}

// Return the unique ResourceName
func (c *CSR) Name() ResourceName {
	return ResourceName{c.ID, RTCSR}
}

// AddDependency registers a depending resource to be retuened by Dependencies()
// Refresh must trigger a rebuild of the resource.
func (c *CSR) Refresh(lookup *Storage) error {
	pk, err := lookup.GetPrivateKey(c.PrivateKey)
	if err != nil {
		return err
	}
	key, err := pk.GetKey()
	if err != nil {
		return err
	}
	subjRes, err := lookup.GetSubject(c.Subject)
	if err != nil {
		return err
	}
	subject := subjRes.GetName()
	subject.CommonName = c.CommonName

	opts := pki.CertificateData{
		Subject:        subject,
		DNSNames:       c.DNSNames,
		EmailAddresses: c.EmailAddresses,
		IPAddresses:    c.IPAddresses,
	}
	csr, err := opts.ToCertificateRequest(key)
	if err != nil {
		return err
	}
	block, err := csr.ToPem()
	if err != nil {
		return err
	}
	block.Headers = map[string]string{"ID": c.ID}
	c.Data = pem.EncodeToMemory(&block)
	return nil
}

// Return the PEM output of the contained resource.
func (c *CSR) Pem() ([]byte, error) { return c.Data, nil }
func (c *CSR) Checksum() []byte     { return Hash(c.Data) }

// DependsOn must return the resource names it is depending on.
func (c *CSR) DependsOn() []ResourceName {
	return []ResourceName{c.PrivateKey}
}

func (c *CSR) GetCSR() (*pki.CertificateRequest, error) {
	// TODO fix this, we must check if there is anything else
	block, _ := pem.Decode(c.Data)
	csr, err := pki.LoadCertificateSignRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	return csr, nil
}

package main

import (
	"encoding/pem"
	"fmt"
	"net"
	"time"

	"github.com/gibheer/pki"
	"github.com/gibheer/pkiadm"
)

type (
	CSR struct {
		// ID is the unique identifier of the CSR.
		ID string

		// Interval represents the refresh timing information.
		Interval Interval

		// The following options are used to generate the content of the CSR.
		DNSNames       []string
		EmailAddresses []string
		IPAddresses    []net.IP

		// PrivateKey is needed to sign the certificate sign request.
		PrivateKey pkiadm.ResourceName
		Subject    pkiadm.ResourceName

		// Data contains the pem representation of the CSR.
		Data []byte
	}
)

// NewCSR creates a new CSR.
func NewCSR(id string, pk, subject pkiadm.ResourceName, dnsNames []string,
	emailAddresses []string, iPAddresses []net.IP, refreshAfter time.Duration,
	invalidAfter time.Duration) (*CSR, error) {
	return &CSR{
		ID:             id,
		Subject:        subject,
		DNSNames:       dnsNames,
		EmailAddresses: emailAddresses,
		IPAddresses:    iPAddresses,
		PrivateKey:     pk,
		Interval: Interval{
			Created:      time.Now(),
			RefreshAfter: refreshAfter,
			InvalidAfter: invalidAfter,
		},
	}, nil
}

// Return the unique ResourceName
func (c *CSR) Name() pkiadm.ResourceName {
	return pkiadm.ResourceName{c.ID, pkiadm.RTCSR}
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
	c.Data = pem.EncodeToMemory(&block)
	c.Interval.LastRefresh = time.Now()
	return nil
}

func (c *CSR) RefreshInterval() Interval {
	return c.Interval
}

// Return the PEM output of the contained resource.
func (c *CSR) Pem() ([]byte, error) { return c.Data, nil }
func (c *CSR) Checksum() []byte     { return Hash(c.Data) }

// DependsOn must return the resource names it is depending on.
func (c *CSR) DependsOn() []pkiadm.ResourceName {
	return []pkiadm.ResourceName{c.PrivateKey}
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

func (s *Server) CreateCSR(inCSR pkiadm.CSR, res *pkiadm.Result) error {
	s.lock()
	defer s.unlock()

	csr, err := NewCSR(
		inCSR.ID,
		inCSR.PrivateKey,
		inCSR.Subject,
		inCSR.DNSNames,
		inCSR.EmailAddresses,
		inCSR.IPAddresses,
		0, 0,
	)
	if err != nil {
		res.SetError(err, "Could not create new private key '%s'", inCSR.ID)
		return nil
	}
	if err := s.storage.AddCSR(csr); err != nil {
		res.SetError(err, "Could not add private key '%s'", inCSR.ID)
		return nil
	}
	return s.store(res)
}
func (s *Server) SetCSR(changeset pkiadm.CSRChange, res *pkiadm.Result) error {
	s.lock()
	defer s.unlock()

	csr, err := s.storage.GetCSR(pkiadm.ResourceName{ID: changeset.CSR.ID, Type: pkiadm.RTCSR})
	if err != nil {
		res.SetError(err, "Could not find private key '%s'", changeset.CSR.ID)
		return nil
	}

	change := changeset.CSR
	for _, field := range changeset.FieldList {
		switch field {
		case "private-key":
			csr.PrivateKey = change.PrivateKey
		case "subject":
			csr.Subject = change.Subject
		case "ip":
			csr.IPAddresses = change.IPAddresses
		case "fqdn":
			csr.DNSNames = change.DNSNames
		case "mail":
			csr.EmailAddresses = change.EmailAddresses
		default:
			res.SetError(fmt.Errorf("unknown field"), "unknown field '%s'", field)
			return nil
		}
	}
	if err := s.storage.Update(pkiadm.ResourceName{ID: csr.ID, Type: pkiadm.RTCSR}); err != nil {
		res.SetError(err, "Could not update private key '%s'", changeset.CSR.ID)
		return nil
	}
	return s.store(res)
}
func (s *Server) DeleteCSR(inCSR pkiadm.ResourceName, res *pkiadm.Result) error {
	s.lock()
	defer s.unlock()

	csr, err := s.storage.GetCSR(pkiadm.ResourceName{ID: inCSR.ID, Type: pkiadm.RTCSR})
	if err != nil {
		res.SetError(err, "Could not find private key '%s'", inCSR.ID)
		return nil
	}

	if err := s.storage.Remove(csr); err != nil {
		res.SetError(err, "Could not remove private key '%s'", csr.ID)
		return nil
	}
	return s.store(res)
}
func (s *Server) ShowCSR(inCSR pkiadm.ResourceName, res *pkiadm.ResultCSR) error {
	s.lock()
	defer s.unlock()

	csr, err := s.storage.GetCSR(pkiadm.ResourceName{ID: inCSR.ID, Type: pkiadm.RTCSR})
	if err != nil {
		res.Result.SetError(err, "Could not find private key '%s'", inCSR.ID)
		return nil
	}
	res.CSRs = []pkiadm.CSR{pkiadm.CSR{
		ID:             csr.ID,
		Subject:        csr.Subject,
		PrivateKey:     csr.PrivateKey,
		EmailAddresses: csr.EmailAddresses,
		DNSNames:       csr.DNSNames,
		IPAddresses:    csr.IPAddresses,
		Checksum:       csr.Checksum(),
	}}
	return nil
}
func (s *Server) ListCSR(filter pkiadm.Filter, res *pkiadm.ResultCSR) error {
	s.lock()
	defer s.unlock()

	for _, csr := range s.storage.CSRs {
		res.CSRs = append(res.CSRs, pkiadm.CSR{
			ID:             csr.ID,
			Subject:        csr.Subject,
			PrivateKey:     csr.PrivateKey,
			EmailAddresses: csr.EmailAddresses,
			DNSNames:       csr.DNSNames,
			IPAddresses:    csr.IPAddresses,
			Checksum:       csr.Checksum(),
		})
	}
	return nil
}

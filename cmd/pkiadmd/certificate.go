package main

import (
	"encoding/pem"
	"fmt"
	"time"

	"github.com/gibheer/pki"
	"github.com/gibheer/pkiadm"
)

type (
	Signer interface {
		Sign(*CSR) (pki.Certificate, error)
	}

	Certificate struct {
		ID string

		IsCA     bool
		Duration time.Duration

		PrivateKey pkiadm.ResourceName
		Serial     pkiadm.ResourceName
		CSR        pkiadm.ResourceName
		CA         pkiadm.ResourceName

		Data []byte
	}
)

func NewCertificate(id string, privateKey, serial, csr, ca pkiadm.ResourceName, selfSign bool, duration time.Duration) (*Certificate, error) {
	return &Certificate{
		ID:         id,
		PrivateKey: privateKey,
		Serial:     serial,
		CSR:        csr,
		CA:         ca,
		IsCA:       selfSign,
		Duration:   duration,
	}, nil
}

// Return the unique ResourceName
func (c *Certificate) Name() pkiadm.ResourceName {
	return pkiadm.ResourceName{c.ID, pkiadm.RTCertificate}
}

// AddDependency registers a depending resource to be retuened by Dependencies()
// Refresh must trigger a rebuild of the resource.
func (c *Certificate) Refresh(lookup *Storage) error {
	var err error
	ca := CASelfSign
	if !c.IsCA {
		ca, err = lookup.GetCA(c.CA)
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
	//cert, err := csr.ToCertificate(pk, opts, ca)
	cert, err := ca.Sign(lookup, csr, opts)
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
func (c *Certificate) DependsOn() []pkiadm.ResourceName {
	res := []pkiadm.ResourceName{
		c.PrivateKey,
		c.Serial,
		c.CSR,
	}
	if !c.IsCA {
		res = append(res, c.CA)
	}
	return res
}

func (s *Server) CreateCertificate(inCert pkiadm.Certificate, res *pkiadm.Result) error {
	s.lock()
	defer s.unlock()

	cert, err := NewCertificate(
		inCert.ID,
		inCert.PrivateKey,
		inCert.Serial,
		inCert.CSR,
		inCert.CA,
		inCert.IsCA,
		inCert.Duration,
	)
	if err != nil {
		res.SetError(err, "Could not create new certificate '%s'", inCert.ID)
		return nil
	}
	if err := s.storage.AddCertificate(cert); err != nil {
		res.SetError(err, "Could not add certificate '%s'", inCert.ID)
		return nil
	}
	return s.store(res)
}

func (s *Server) SetCertificate(changeset pkiadm.CertificateChange, res *pkiadm.Result) error {
	s.lock()
	defer s.unlock()

	cert, err := s.storage.GetCertificate(pkiadm.ResourceName{ID: changeset.Certificate.ID, Type: pkiadm.RTCertificate})
	if err != nil {
		res.SetError(err, "Could not find certficate '%s'", changeset.Certificate.ID)
		return nil
	}

	change := changeset.Certificate
	for _, field := range changeset.FieldList {
		switch field {
		case "duration":
			cert.Duration = change.Duration
		case "private":
			cert.PrivateKey = change.PrivateKey
		case "csr":
			cert.CSR = change.CSR
		case "serial":
			cert.Serial = change.Serial
		case "ca":
			cert.CA = change.CA
		case "self-sign":
			cert.IsCA = change.IsCA
		default:
			res.SetError(fmt.Errorf("unknown field"), "unknown field '%s'", field)
			return nil
		}
	}
	if err := s.storage.Update(cert.Name()); err != nil {
		res.SetError(err, "Could not update certificate '%s'", changeset.Certificate.ID)
		return nil
	}
	return s.store(res)
}

func (s *Server) DeleteCertificate(inCert pkiadm.ResourceName, res *pkiadm.Result) error {
	s.lock()
	defer s.unlock()

	cert, err := s.storage.GetCertificate(pkiadm.ResourceName{ID: inCert.ID, Type: pkiadm.RTCertificate})
	if err != nil {
		res.SetError(err, "Could not find certificate '%s'", inCert.ID)
		return nil
	}

	if err := s.storage.Remove(cert); err != nil {
		res.SetError(err, "Could not remove certificate '%s'", cert.ID)
		return nil
	}
	return s.store(res)
}
func (s *Server) ShowCertificate(inCert pkiadm.ResourceName, res *pkiadm.ResultCertificate) error {
	s.lock()
	defer s.unlock()

	cert, err := s.storage.GetCertificate(pkiadm.ResourceName{ID: inCert.ID, Type: pkiadm.RTCertificate})
	if err != nil {
		res.Result.SetError(err, "Could not find certificate '%s'", inCert.ID)
		return nil
	}
	res.Certificates = []pkiadm.Certificate{pkiadm.Certificate{
		ID:         cert.ID,
		Duration:   cert.Duration,
		PrivateKey: cert.PrivateKey,
		Serial:     cert.Serial,
		CA:         cert.CA,
		CSR:        cert.CSR,
		Checksum:   cert.Checksum(),
	}}
	return nil
}
func (s *Server) ListCertificate(filter pkiadm.Filter, res *pkiadm.ResultCertificate) error {
	s.lock()
	defer s.unlock()

	for _, cert := range s.storage.Certificates {
		res.Certificates = append(res.Certificates, pkiadm.Certificate{
			ID:         cert.ID,
			Duration:   cert.Duration,
			PrivateKey: cert.PrivateKey,
			Serial:     cert.Serial,
			CA:         cert.CA,
			CSR:        cert.CSR,
			Checksum:   cert.Checksum(),
		})
	}
	return nil
}

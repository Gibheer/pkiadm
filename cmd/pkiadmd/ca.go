package main

import (
	"log"

	"github.com/gibheer/pki"
	"github.com/gibheer/pkiadm"
)

var (
	CASelfSign = &CA{
		ID:   "self-sign",
		Type: pkiadm.CALocal,
	}
)

type (
	// CA is an instance that can sign certificates. When a certificate needs an
	// update, the given CSR is signed by the CA.
	// A CA can be responsible for multiple certificates to sign.
	CA struct {
		ID          string
		Type        pkiadm.CAType
		Certificate pkiadm.ResourceName
	}
)

func NewCA(id string, caType pkiadm.CAType, cert pkiadm.ResourceName) (*CA, error) {
	ca := &CA{
		ID:          id,
		Type:        caType,
		Certificate: cert,
	}
	return ca, nil
}

// Sign the certificate sign request with this CA
func (ca *CA) Sign(lookup *Storage, csr pkiadm.ResourceName, opts pki.CertificateOptions) (*pki.Certificate, error) {
	var caCert *pki.Certificate
	var pk pki.PrivateKey
	var caCertDef *Certificate

	csrRes, err := lookup.GetCSR(csr)
	if err != nil {
		return nil, err
	}
	csrIns, err := csrRes.GetCSR()
	if err != nil {
		return nil, err
	}

	if ca == CASelfSign {
		pkDef, err := lookup.GetPrivateKey(csrRes.PrivateKey)
		if err != nil {
			return nil, err
		}
		pk, err = pkDef.GetKey()
		if err != nil {
			return nil, err
		}
		caCertDef = &Certificate{ID: "self-signed"}
	} else {
		caCertDef, err = lookup.GetCertificate(ca.Certificate)
		if err != nil {
			return nil, err
		}
		caCert, err = caCertDef.GetCertificate()
		if err != nil {
			return nil, err
		}
		pkDef, err := lookup.GetPrivateKey(caCertDef.PrivateKey)
		if err != nil {
			return nil, err
		}
		pk, err = pkDef.GetKey()
		if err != nil {
			return nil, err
		}
	}

	log.Printf("ca '%s' signing csr '%s' using cert '%s'", ca.ID, csr.ID, caCertDef.ID)
	return csrIns.ToCertificate(pk, opts, caCert)
}

// Return the unique ResourceName
func (ca *CA) Name() pkiadm.ResourceName {
	return pkiadm.ResourceName{ca.ID, pkiadm.RTCA}
}

// AddDependency registers a depending resource to be retuened by Dependencies()
// Refresh must trigger a rebuild of the resource.
func (ca *CA) Refresh(*Storage) error {
	return nil
}

// Return the PEM output of the contained resource.
func (ca *CA) Pem() ([]byte, error) { return []byte{}, nil }
func (ca *CA) Checksum() []byte     { return []byte{} }

// DependsOn must return the resource names it is depending on.
func (ca *CA) DependsOn() []pkiadm.ResourceName {
	return []pkiadm.ResourceName{
		ca.Certificate,
	}
}

func (s *Server) CreateCA(inCA pkiadm.CA, res *pkiadm.Result) error {
	s.lock()
	defer s.unlock()

	ca, err := NewCA(inCA.ID, inCA.Type, inCA.Certificate)
	if err != nil {
		res.SetError(err, "could not create CA '%s'", inCA.ID)
		return nil
	}
	if err := s.storage.AddCA(ca); err != nil {
		res.SetError(err, "could not add CA '%s'", inCA.ID)
		return nil
	}
	return s.store(res)
}

func (s *Server) SetCA(change pkiadm.CAChange, res *pkiadm.Result) error {
	s.lock()
	defer s.unlock()

	ca, err := s.storage.GetCA(pkiadm.ResourceName{ID: change.CA.ID, Type: pkiadm.RTCA})
	if err != nil {
		res.SetError(err, "could not find CA '%s'", change.CA.ID)
		return nil
	}
	for _, field := range change.FieldList {
		switch field {
		case "type":
			ca.Type = change.CA.Type
		case "certificate":
			ca.Certificate = change.CA.Certificate
		}
	}
	return s.store(res)
}

func (s *Server) DeleteCA(inCA pkiadm.CA, res *pkiadm.Result) error {
	s.lock()
	defer s.unlock()

	ca, err := s.storage.GetCA(pkiadm.ResourceName{inCA.ID, pkiadm.RTCA})
	if err != nil {
		res.SetError(err, "Could not find ca '%s'", ca.ID)
		return nil
	}

	if err := s.storage.Remove(ca); err != nil {
		res.SetError(err, "Could not remove ca '%s'", ca.ID)
		return nil
	}
	return s.store(res)
}

func (s *Server) ShowCA(inCA pkiadm.CA, res *pkiadm.ResultCA) error {
	s.lock()
	defer s.unlock()

	ca, err := s.storage.GetCA(pkiadm.ResourceName{ID: inCA.ID, Type: pkiadm.RTCA})
	if err != nil {
		res.Result.SetError(err, "Could not find CA '%s'", inCA.ID)
		return nil
	}
	res.CAs = []pkiadm.CA{pkiadm.CA{
		ID:          ca.ID,
		Type:        ca.Type,
		Certificate: ca.Certificate,
	}}
	return nil
}

func (s *Server) ListCA(filter pkiadm.Filter, res *pkiadm.ResultCA) error {
	s.lock()
	defer s.unlock()

	for _, ca := range s.storage.CAs {
		res.CAs = append(res.CAs, pkiadm.CA{
			ID:          ca.ID,
			Type:        ca.Type,
			Certificate: ca.Certificate,
		})
	}
	return nil
}

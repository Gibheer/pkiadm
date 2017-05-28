package main

import (
	"crypto/x509/pkix"
	"fmt"

	"github.com/gibheer/pkiadm"
)

type (
	Subject struct {
		ID   string
		Data pkix.Name
	}
)

// Create a new subject resource. The commonName of the name is not used at the
// moment.
func NewSubject(id string, name pkix.Name) (*Subject, error) {
	return &Subject{
		ID:   id,
		Data: name,
	}, nil
}

// Return the unique ResourceName
func (sub *Subject) Name() ResourceName { return ResourceName{sub.ID, RTSubject} }

// AddDependency registers a depending resource to be retuened by Dependencies()
// Refresh must trigger a rebuild of the resource.
// This is a NOOP as it does not have any dependencies.
func (sub *Subject) Refresh(_ *Storage) error { return nil }

// Return the PEM output of the contained resource.
func (sub *Subject) Pem() ([]byte, error) { return []byte{}, nil }
func (sub *Subject) Checksum() []byte     { return []byte{} }

// DependsOn must return the resource names it is depending on.
func (sub *Subject) DependsOn() []ResourceName { return []ResourceName{} }

// GetName returns the stored name definition.
func (sub *Subject) GetName() pkix.Name {
	return sub.Data
}

// CreateSubject is the RPC endpoint to create a new subject.
func (s *Server) CreateSubject(inSubj pkiadm.Subject, res *pkiadm.Result) error {
	s.lock()
	defer s.unlock()

	subj, err := NewSubject(inSubj.ID, inSubj.Name)
	if err != nil {
		res.SetError(err, "Could not create new subject '%s'", inSubj.ID)
		return nil
	}
	if err := s.storage.AddSubject(subj); err != nil {
		res.SetError(err, "Could not add subject '%s'", inSubj.ID)
		return nil
	}
	return s.store(res)
}

// SetSubject is the RPC endpoint to adjust fields on a subject.
func (s *Server) SetSubject(changeset pkiadm.SubjectChange, res *pkiadm.Result) error {
	s.lock()
	defer s.unlock()

	subj, err := s.storage.GetSubject(ResourceName{ID: changeset.Subject.ID, Type: RTSubject})
	if err != nil {
		res.SetError(err, "Could not find subject '%s'", changeset.Subject.ID)
		return nil
	}
	changes := changeset.Subject.Name
	for _, field := range changeset.FieldList {
		switch field {
		case "serial":
			subj.Data.SerialNumber = changes.SerialNumber
		case "common-name":
			subj.Data.CommonName = changes.CommonName
		case "country":
			subj.Data.Country = changes.Country
		case "org":
			subj.Data.Organization = changes.Organization
		case "org-unit":
			subj.Data.OrganizationalUnit = changes.OrganizationalUnit
		case "locality":
			subj.Data.Locality = changes.Locality
		case "province":
			subj.Data.Province = changes.Province
		case "street":
			subj.Data.StreetAddress = changes.StreetAddress
		case "code":
			subj.Data.PostalCode = changes.PostalCode
		default:
			res.SetError(fmt.Errorf("unknown field"), "unknown field '%s'", field)
			return nil
		}
	}
	if err := s.storage.Update(ResourceName{ID: subj.ID, Type: RTSubject}); err != nil {
		res.SetError(err, "Could not update subject '%s'", changeset.Subject.ID)
		return nil
	}
	return s.store(res)
}

// ListSubjects is the RPC endpoint to list all available subjects.
func (s *Server) ListSubjects(filter pkiadm.Filter, res *pkiadm.ResultSubjects) error {
	s.lock()
	defer s.unlock()

	for _, subj := range s.storage.Subjects {
		res.Subjects = append(res.Subjects, pkiadm.Subject{
			ID:   subj.ID,
			Name: subj.GetName(),
		})
	}
	return nil
}

// DeleteSubject is the RPC endpoint to delete a subject.
func (s *Server) DeleteSubject(inSubj pkiadm.ResourceName, res *pkiadm.Result) error {
	s.lock()
	defer s.unlock()

	subj, err := s.storage.Get(ResourceName{ID: inSubj.ID, Type: RTSubject})
	if err == ENotFound {
		return nil
	} else if err != nil {
		res.SetError(err, "Could not find resource '%s'", inSubj)
		return nil
	}
	if err := s.storage.Remove(subj); err != nil {
		res.SetError(err, "Could not remove subject '%s'", inSubj)
		return nil
	}
	return s.store(res)
}

// ShowSubject is the RPC endpoint to get a single subject resource for detailed
// inspection.
func (s *Server) ShowSubject(inSubj pkiadm.ResourceName, res *pkiadm.ResultSubjects) error {
	s.lock()
	defer s.unlock()

	subj, err := s.storage.GetSubject(ResourceName{ID: inSubj.ID, Type: RTSubject})
	if err == ENotFound {
		return nil
	} else if err != nil {
		res.Result.SetError(err, "could not find resource '%s'", inSubj)
		return nil
	}
	res.Subjects = []pkiadm.Subject{
		pkiadm.Subject{
			ID:   subj.ID,
			Name: subj.GetName(),
		},
	}
	return nil
}

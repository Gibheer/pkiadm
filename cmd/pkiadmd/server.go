package main

import (
	"log"
	"sync"

	"github.com/gibheer/pkiadm"
)

type (
	Server struct {
		storage *Storage
		mu      *sync.Mutex
	}
)

func NewServer(storage *Storage) (*Server, error) {
	return &Server{storage, &sync.Mutex{}}, nil
}

func (s *Server) lock() {
	s.mu.Lock()
}
func (s *Server) unlock() {
	s.mu.Unlock()
}
func (s *Server) store(res *pkiadm.Result) error {
	if err := s.storage.store(); err != nil {
		log.Printf("error when storing changes: %+v", err)
		res.SetError(err, "could not save database")
	}
	return nil
}

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
		}
	}
	if err := s.storage.Update(ResourceName{ID: subj.ID, Type: RTSubject}); err != nil {
		res.SetError(err, "Could update resource '%s'", changeset.Subject.ID)
		return nil
	}
	return s.store(res)
}

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

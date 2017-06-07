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

func (s *Server) List(filter pkiadm.Filter, result *pkiadm.ResultResource) error {
	for _, res := range s.storage.PrivateKeys {
		result.Resources = append(result.Resources, res.Name())
	}
	for _, res := range s.storage.PublicKeys {
		result.Resources = append(result.Resources, res.Name())
	}
	for _, res := range s.storage.Locations {
		result.Resources = append(result.Resources, res.Name())
	}
	for _, res := range s.storage.Certificates {
		result.Resources = append(result.Resources, res.Name())
	}
	for _, res := range s.storage.CSRs {
		result.Resources = append(result.Resources, res.Name())
	}
	for _, res := range s.storage.Serials {
		result.Resources = append(result.Resources, res.Name())
	}
	for _, res := range s.storage.Subjects {
		result.Resources = append(result.Resources, res.Name())
	}
	return nil
}

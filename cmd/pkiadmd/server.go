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
	resources := s.storage.List()
	result.Resources = make([]pkiadm.ResourceName, len(resources))
	for i, res := range resources {
		result.Resources[i] = res.Name()
	}
	return nil
}

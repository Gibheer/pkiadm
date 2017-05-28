package main

import (
	"crypto/x509/pkix"
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

package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"

	"github.com/gibheer/pkiadm"
)

const (
	ENoPathGiven = Error("no path given")
)

type (
	Location struct {
		ID string

		PreCommand  string
		PostCommand string

		Path         string
		Dependencies []pkiadm.ResourceName
	}
)

func NewLocation(id, path, preCom, postCom string, res []pkiadm.ResourceName) (*Location, error) {
	if id == "" {
		return nil, ENoIDGiven
	}
	if path == "" {
		return nil, ENoPathGiven
	}
	l := &Location{
		ID:           id,
		Path:         path,
		Dependencies: res,
	}
	return l, nil
}

func (l *Location) Name() pkiadm.ResourceName {
	return pkiadm.ResourceName{l.ID, pkiadm.RTLocation}
}

// Refresh writes all resources into the single file.
func (l *Location) Refresh(lookup *Storage) error {
	raw := []byte{}
	for _, rn := range l.DependsOn() {
		r, err := lookup.Get(rn)
		if err != nil {
			return err
		}
		output, err := r.Pem()
		if err != nil {
			return err
		}
		raw = append(raw, output...)
	}
	if l.PreCommand != "" {
		log.Printf("location '%s' is updating '%s' - pre '%s'", l.ID, l.Path, l.PreCommand)
		cmd := exec.Command(l.PreCommand, l.Path)
		if err := cmd.Run(); err != nil {
			return err
		}
	}
	log.Printf("location '%s' is updating '%s'", l.ID, l.Path)
	if err := ioutil.WriteFile(l.Path, raw, 0600); err != nil {
		log.Printf("could not write location '%s': %s", l.ID, err)
		return err
	}
	if l.PostCommand != "" {
		log.Printf("location '%s' is updating '%s' - post '%s'", l.ID, l.Path, l.PostCommand)
		cmd := exec.Command(l.PostCommand, l.Path)
		if err := cmd.Run(); err != nil {
			return err
		}
	}
	return nil
}

func (l *Location) DependsOn() []pkiadm.ResourceName { return l.Dependencies }

// Pem is not used by location, as it does not contain any data.
func (l *Location) Pem() ([]byte, error) { return []byte{}, nil }

// Checksum is not used by Location, as it does not contain any data.
func (l *Location) Checksum() []byte { return []byte{} }

func (s *Server) CreateLocation(inLoc pkiadm.Location, res *pkiadm.Result) error {
	s.lock()
	defer s.unlock()

	deps := []pkiadm.ResourceName{}
	for _, dep := range inLoc.Dependencies {
		deps = append(deps, pkiadm.ResourceName{ID: dep.ID, Type: dep.Type})
	}
	loc, err := NewLocation(inLoc.ID, inLoc.Path, inLoc.PreCommand, inLoc.PostCommand, deps)
	if err != nil {
		res.SetError(err, "Could not create location '%s'", inLoc.ID)
		return nil
	}
	if err := s.storage.AddLocation(loc); err != nil {
		res.SetError(err, "Could not add location '%s'", inLoc.ID)
		return nil
	}
	return s.store(res)
}

func (s *Server) SetLocation(changeset pkiadm.LocationChange, res *pkiadm.Result) error {
	s.lock()
	defer s.unlock()

	changed := changeset.Location
	locName := pkiadm.ResourceName{changed.ID, pkiadm.RTLocation}
	loc, err := s.storage.GetLocation(locName)
	if err != nil {
		res.SetError(err, "could not find location '%s'", changeset.Location.ID)
		return nil
	}
	for _, field := range changeset.FieldList {
		switch field {
		case "path":
			// TODO remove old file?
			loc.Path = changed.Path
		case "pre-cmd":
			loc.PreCommand = changed.PreCommand
		case "post-cmd":
			loc.PostCommand = changed.PostCommand
		case "resources":
			loc.Dependencies = changed.Dependencies
		default:
			res.SetError(fmt.Errorf("unknown field"), "unknown field '%s'", field)
			return nil
		}
	}
	if err := s.storage.Update(locName); err != nil {
		log.Printf("could not update location '%s': %s", loc.ID, err)
		res.SetError(err, "Could not update location '%s'", loc.ID)
		return nil
	}
	return s.store(res)
}

func (s *Server) DeleteLocation(inLoc pkiadm.Location, res *pkiadm.Result) error {
	s.lock()
	defer s.unlock()

	loc, err := s.storage.GetLocation(pkiadm.ResourceName{inLoc.ID, pkiadm.RTLocation})
	if err != nil {
		res.SetError(err, "could not find location '%s'", inLoc.ID)
		return nil
	}

	if err := os.Remove(loc.Path); err != nil {
		res.SetError(err, "Could not remove file '%s' for location '%s'", loc.Path, loc.ID)
		return nil
	}
	if err := s.storage.Remove(loc); err != nil {
		res.SetError(err, "Could not remove location '%s'", loc.ID)
		return nil
	}
	if loc.PostCommand != "" {
		cmd := exec.Command(loc.PostCommand, loc.Path)
		if err := cmd.Run(); err != nil {
			res.SetError(err, "Could not run post command after deleting '%s'", loc.ID)
			return nil
		}
	}
	return s.store(res)
}

func (s *Server) ShowLocation(inLoc pkiadm.PrivateKey, res *pkiadm.ResultLocations) error {
	s.lock()
	defer s.unlock()

	loc, err := s.storage.GetLocation(pkiadm.ResourceName{inLoc.ID, pkiadm.RTLocation})
	if err != nil {
		res.Result.SetError(err, "Could not find location '%s'", inLoc.ID)
		return nil
	}
	res.Locations = []pkiadm.Location{pkiadm.Location{
		ID:           loc.ID,
		Path:         loc.Path,
		PreCommand:   loc.PreCommand,
		PostCommand:  loc.PostCommand,
		Dependencies: loc.Dependencies,
	}}
	return nil
}

func (s *Server) ListLocation(filter pkiadm.Filter, res *pkiadm.ResultLocations) error {
	s.lock()
	defer s.unlock()

	for _, loc := range s.storage.Locations {
		res.Locations = append(res.Locations, pkiadm.Location{
			ID:           loc.ID,
			Path:         loc.Path,
			PreCommand:   loc.PreCommand,
			PostCommand:  loc.PostCommand,
			Dependencies: loc.Dependencies,
		})
	}
	return nil
}

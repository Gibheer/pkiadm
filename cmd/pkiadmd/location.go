package main

import (
	"fmt"
)

const (
	ENoPathGiven = Error("no path given")
)

type (
	Location struct {
		ID string

		Path         string
		Dependencies []ResourceName
	}
)

func NewLocation(id, path string, res []ResourceName) (*Location, error) {
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

func (l *Location) Name() ResourceName {
	return ResourceName{l.ID, RTLocation}
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
	// TODO write to file
	fmt.Printf("found %d characters for file: %s\n", len(raw), l.Path)
	return nil
}

func (l *Location) DependsOn() []ResourceName { return l.Dependencies }

// Pem is not used by location, as it does not contain any data.
func (l *Location) Pem() ([]byte, error) { return []byte{}, nil }

// Checksum is not used by Location, as it does not contain any data.
func (l *Location) Checksum() []byte { return []byte{} }

//func (l *Location) MarshalJSON() ([]byte, error) {
//	return json.Marshal(*l)
//}
//func (l *Location) UnmarshalJSON(raw []byte) error {
//	return json.Unmarshal(raw, l)
//}

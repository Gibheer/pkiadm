package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"sort"
	"time"

	"github.com/gibheer/pkiadm"
	"github.com/pkg/errors"
)

type (
	// Storage is used to add and lookup resources and manages the dependency
	// chain on an update.
	Storage struct {
		// path to the place where the storage should be stored.
		path         string
		PrivateKeys  map[string]*PrivateKey
		PublicKeys   map[string]*PublicKey
		Locations    map[string]*Location
		Certificates map[string]*Certificate
		CSRs         map[string]*CSR
		Serials      map[string]*Serial
		Subjects     map[string]*Subject
		CAs          map[string]*CA
		// dependencies maps from a resource name to all resources which depend
		// on it.
		dependencies map[string]map[string]Resource
		// refresh order contains all resources in the order they need to be
		// refreshed next.
		refreshOrder RefreshList
		refreshTimer *time.Timer
	}

	// RefreshList is a list of resources
	RefreshList []RefreshSet
	// RefreshSet contains the vital information to decide, when to refresh
	// the specified resource.
	RefreshSet struct {
		Name     pkiadm.ResourceName
		Interval Interval
	}
)

// NewStorage builds a new storage instance and loads available data from the
// provided file path.
func NewStorage(path string) (*Storage, error) {
	s := &Storage{
		path:         path,
		PrivateKeys:  map[string]*PrivateKey{},
		PublicKeys:   map[string]*PublicKey{},
		Locations:    map[string]*Location{},
		Certificates: map[string]*Certificate{},
		CSRs:         map[string]*CSR{},
		Serials:      map[string]*Serial{},
		Subjects:     map[string]*Subject{},
		CAs:          map[string]*CA{},
		dependencies: map[string]map[string]Resource{},
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// load will restore the state from the file to the storage and overwrite
// already existing resources.
func (s *Storage) load() error {
	raw, err := ioutil.ReadFile(s.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, s); err != nil {
		return err
	}
	if err := s.refreshDependencies(); err != nil {
		return err
	}
	s.scanForRefresh()
	return nil
}

// refreshDependencies updates the inter resource dependencies.
func (s *Storage) refreshDependencies() error {
	// TODO do something about broken dependencies
	for _, se := range s.Serials {
		_ = s.addDependency(se) // ignore errors here, as dependencies might be broken
	}
	for _, subj := range s.Subjects {
		_ = s.addDependency(subj)
	}
	for _, pk := range s.PrivateKeys {
		_ = s.addDependency(pk)
	}
	for _, pub := range s.PublicKeys {
		_ = s.addDependency(pub)
	}
	for _, csr := range s.CSRs {
		_ = s.addDependency(csr)
	}
	for _, cert := range s.Certificates {
		_ = s.addDependency(cert)
	}
	for _, l := range s.Locations {
		_ = s.addDependency(l)
	}
	for _, ca := range s.CAs {
		_ = s.addDependency(ca)
	}
	return nil
}

// scanForRefresh updates the list of resources that need an update.
func (s *Storage) scanForRefresh() {
	if s.refreshTimer != nil {
		s.refreshTimer.Stop()
	}
	refList := RefreshList{}
	for _, res := range s.PrivateKeys {
		refList.Add(res)
	}
	for _, res := range s.PublicKeys {
		refList.Add(res)
	}
	for _, res := range s.CSRs {
		refList.Add(res)
	}
	for _, res := range s.Certificates {
		refList.Add(res)
	}
	for _, res := range s.Locations {
		refList.Add(res)
	}
	sort.Sort(refList)
	if len(refList) == 0 {
		log.Println("nothing found to refresh, looking again in 24h")
		s.refreshTimer = time.AfterFunc(24*time.Hour, s.scanForRefresh)
		return
	}
	s.refreshOrder = refList
	duration := refList[0].Interval.LastRefresh.
		Add(refList[0].Interval.RefreshAfter).
		Sub(time.Now())
	if duration <= 5*time.Second {
		duration = 5 * time.Second
	}
	log.Printf("next refresh planned for '%s' in %s", refList[0].Name, duration)
	s.refreshTimer = time.AfterFunc(
		duration,
		s.refresh,
	)
}

func (s *Storage) refresh() {
	if len(s.refreshOrder) == 0 {
		return
	}
	resName := s.refreshOrder[0].Name
	res, err := s.Get(resName)
	if err != nil {
		// the resource doesn't exist anymore, so just rescan
		log.Printf("resource to refresh has gone away: %s", resName)
		goto rescan
	}
	if err := res.Refresh(s); err != nil {
		log.Printf("error refreshing resource '%s': %s", res.Name(), err)
	}
	if err := s.store(); err != nil {
		log.Printf("could not update resources: %s", err)
	}
rescan:
	log.Printf("rescanning for new entries")
	s.scanForRefresh()
}

// addDependency adds a resource to the dependency graph.
func (s *Storage) addDependency(r Resource) error {
	for _, rn := range r.DependsOn() {
		_, err := s.Get(rn)
		if err != nil {
			return Error(fmt.Sprintf("problem with dependency '%s': %s", rn, err))
		}
		deps, found := s.dependencies[rn.String()]
		if !found {
			s.dependencies[rn.String()] = map[string]Resource{r.Name().String(): r}
		} else {
			deps[r.Name().String()] = r
		}
	}
	return nil
}

// store writes the content of the storage to the disk in json format.
func (s *Storage) store() error {
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		log.Printf("could not marshal data: %s", err)
		return err
	}
	if err := ioutil.WriteFile(s.path, raw, 0600); err != nil {
		log.Printf("could not write to file '%s': %s", s.path, err)
		return err
	}
	return nil
}

// AddSerial adds a serial to the storage and refreshes the dependencies.
func (s *Storage) AddSerial(se *Serial) error {
	if err := se.Refresh(s); err != nil {
		return err
	}
	s.Serials[se.Name().ID] = se
	s.scanForRefresh()
	return s.addDependency(se)
}

// AddSubject adds a new subject to the storage and refreshes the dependencies.
func (s *Storage) AddSubject(se *Subject) error {
	if _, found := s.Subjects[se.Name().ID]; found {
		return EAlreadyExist
	}
	if err := se.Refresh(s); err != nil {
		return err
	}
	s.Subjects[se.Name().ID] = se
	s.scanForRefresh()
	return s.addDependency(se)
}

// AddPrivateKey adds a private key to the storage and refreshes the dependencies.
func (s *Storage) AddPrivateKey(pk *PrivateKey) error {
	if err := pk.Refresh(s); err != nil {
		return err
	}
	s.PrivateKeys[pk.Name().ID] = pk
	s.scanForRefresh()
	return s.addDependency(pk)
}

// AddPublicKey adds a public key to the storage and refreshes the dependencies.
func (s *Storage) AddPublicKey(pub *PublicKey) error {
	if err := pub.Refresh(s); err != nil {
		return err
	}
	s.PublicKeys[pub.Name().ID] = pub
	s.scanForRefresh()
	return s.addDependency(pub)
}

// AddCertificate adds a certificate to the storage and refreshes the dependencies.
func (s *Storage) AddCertificate(cert *Certificate) error {
	if err := cert.Refresh(s); err != nil {
		return err
	}
	s.Certificates[cert.Name().ID] = cert
	s.scanForRefresh()
	return s.addDependency(cert)
}

// AddCSR adds a CSR to the storage and refreshes the dependencies.
func (s *Storage) AddCSR(csr *CSR) error {
	if err := csr.Refresh(s); err != nil {
		return err
	}
	s.CSRs[csr.Name().ID] = csr
	s.scanForRefresh()
	return s.addDependency(csr)
}

// AddLocation adds a location to the storage and refreshes the dependencies.
func (s *Storage) AddLocation(l *Location) error {
	if err := l.Refresh(s); err != nil {
		return err
	}
	s.Locations[l.Name().ID] = l
	s.scanForRefresh()
	return s.addDependency(l)
}

func (s *Storage) AddCA(ca *CA) error {
	if err := ca.Refresh(s); err != nil {
		return err
	}
	s.CAs[ca.Name().ID] = ca
	s.scanForRefresh()
	return s.addDependency(ca)
}

// Get figures out the resource to the ResourceName if available.
func (s *Storage) Get(r pkiadm.ResourceName) (Resource, error) {
	if r.ID == "" {
		return nil, ENoIDGiven
	}
	switch r.Type {
	case pkiadm.RTSerial:
		return s.GetSerial(r)
	case pkiadm.RTSubject:
		return s.GetSubject(r)
	case pkiadm.RTPrivateKey:
		return s.GetPrivateKey(r)
	case pkiadm.RTPublicKey:
		return s.GetPublicKey(r)
	case pkiadm.RTCSR:
		return s.GetCSR(r)
	case pkiadm.RTCertificate:
		return s.GetCertificate(r)
	case pkiadm.RTLocation:
		return s.GetLocation(r)
	case pkiadm.RTCA:
		return s.GetCA(r)
	default:
		return nil, EUnknownType
	}
}

// GetSerial returns the Serial matching the ResourceName.
func (s *Storage) GetSerial(r pkiadm.ResourceName) (*Serial, error) {
	if se, found := s.Serials[r.ID]; found {
		return se, nil
	}
	return nil, errors.Wrapf(ENotFound, "no serial with id '%s' found", r)
}

// GetSubject returns the Subject matching the ResourceName.
func (s *Storage) GetSubject(r pkiadm.ResourceName) (*Subject, error) {
	if se, found := s.Subjects[r.ID]; found {
		return se, nil
	}
	return nil, errors.Wrapf(ENotFound, "no subject with id '%s' found", r)
}

// GetPrivateKey returns the PrivateKey to the ResourceName.
func (s *Storage) GetPrivateKey(r pkiadm.ResourceName) (*PrivateKey, error) {
	if pk, found := s.PrivateKeys[r.ID]; found {
		return pk, nil
	}
	return nil, errors.Wrapf(ENotFound, "no private key with id '%s' found", r)
}

// GetPublicKey returns the PublicKey to the ResourceName.
func (s *Storage) GetPublicKey(r pkiadm.ResourceName) (*PublicKey, error) {
	if res, found := s.PublicKeys[r.ID]; found {
		return res, nil
	}
	return nil, errors.Wrapf(ENotFound, "no public key with id '%s' found", r)
}

// GetCSR returns the CSR to the CSR.
func (s *Storage) GetCSR(r pkiadm.ResourceName) (*CSR, error) {
	if res, found := s.CSRs[r.ID]; found {
		return res, nil
	}
	return nil, errors.Wrapf(ENotFound, "no CSR with id '%s' found", r)
}

// GetCertificate returns the Certificate matching the ResourceName.
func (s *Storage) GetCertificate(r pkiadm.ResourceName) (*Certificate, error) {
	if res, found := s.Certificates[r.ID]; found {
		return res, nil
	}
	return nil, errors.Wrapf(ENotFound, "no certificate with id '%s' found", r)
}

// GetLocation returns the Location matching the ResourceName.
func (s *Storage) GetLocation(r pkiadm.ResourceName) (*Location, error) {
	if res, found := s.Locations[r.ID]; found {
		return res, nil
	}
	return nil, errors.Wrapf(ENotFound, "no location with id '%s' found", r)
}

// GetCA returns the CA matching the resource name.
func (s *Storage) GetCA(r pkiadm.ResourceName) (*CA, error) {
	if res, found := s.CAs[r.ID]; found {
		return res, nil
	}
	return nil, errors.Wrapf(ENotFound, "no CA with id '%s' found", r)
}

// Remove takes a resource and removes it from the system.
func (s *Storage) Remove(r Resource) error {
	// TODO implement unable to remove when having dependencies
	switch r.Name().Type {
	case pkiadm.RTSerial:
		delete(s.Serials, r.Name().ID)
	case pkiadm.RTSubject:
		delete(s.Subjects, r.Name().ID)
	case pkiadm.RTPrivateKey:
		delete(s.PrivateKeys, r.Name().ID)
	case pkiadm.RTPublicKey:
		delete(s.PublicKeys, r.Name().ID)
	case pkiadm.RTCSR:
		delete(s.CSRs, r.Name().ID)
	case pkiadm.RTCertificate:
		delete(s.Certificates, r.Name().ID)
	case pkiadm.RTLocation:
		delete(s.Locations, r.Name().ID)
	case pkiadm.RTCA:
		delete(s.CAs, r.Name().ID)
	default:
		return EUnknownType
	}
	for _, rn := range r.DependsOn() {
		// TODO handle refresh of dependant resources or block the deletion
		if deps, found := s.dependencies[rn.String()]; found {
			delete(deps, r.Name().String())
		}
	}
	s.scanForRefresh()
	return nil
}

// Update sends a refresh through all resources depending on the one given.
func (s *Storage) Update(rn pkiadm.ResourceName) error {
	r, err := s.Get(rn)
	if err != nil {
		return err
	}
	updateOrder := []Resource{r}
	checkList := map[string]bool{rn.String(): true}
	depsToCheck := []Resource{}
	for _, nextDep := range s.dependencies[rn.String()] {
		depsToCheck = append(depsToCheck, nextDep)
	}

	var dep Resource
	for {
		if len(depsToCheck) == 0 {
			break
		}
		dep, depsToCheck = depsToCheck[0], depsToCheck[1:]
		if _, found := checkList[dep.Name().String()]; found {
			continue
		}
		updateOrder = append(updateOrder, dep)
		checkList[dep.Name().String()] = true
		for _, nextDep := range s.dependencies[dep.Name().String()] {
			depsToCheck = append(depsToCheck, nextDep)
		}
	}

	for _, dep := range updateOrder {
		log.Printf("refreshing resource '%s' because of '%s'", dep.Name(), rn.String())
		if err := dep.Refresh(s); err != nil {
			return err
		}
	}
	s.scanForRefresh()
	return nil
}

// List returns all currently registered resources.
func (s *Storage) List() []Resource {
	resources := []Resource{}
	for _, res := range s.PrivateKeys {
		resources = append(resources, res)
	}
	for _, res := range s.PublicKeys {
		resources = append(resources, res)
	}
	for _, res := range s.Locations {
		resources = append(resources, res)
	}
	for _, res := range s.Certificates {
		resources = append(resources, res)
	}
	for _, res := range s.CSRs {
		resources = append(resources, res)
	}
	for _, res := range s.Serials {
		resources = append(resources, res)
	}
	for _, res := range s.Subjects {
		resources = append(resources, res)
	}
	return resources
}

// Add adds a resource to the refreshList when it should be refreshed.
func (refList *RefreshList) Add(res Resource) {
	refSet := RefreshSet{
		Name:     res.Name(),
		Interval: res.RefreshInterval(),
	}
	if refSet.Interval.RefreshAfter <= 0 {
		return
	}
	newRefList := append(*refList, refSet)
	*refList = newRefList
}

// Len is the number of elements in the collection.
func (refList RefreshList) Len() int { return len(refList) }

// Less reports whether the element with
// index i should sort before the element with index j.
func (refList RefreshList) Less(i, j int) bool {
	return 0 > refList[i].Interval.LastRefresh.Add(
		refList[i].Interval.RefreshAfter,
	).Sub(
		refList[j].Interval.LastRefresh.Add(
			refList[j].Interval.RefreshAfter),
	)
}

// Swap swaps the elements with indexes i and j.
func (refList RefreshList) Swap(i, j int) {
	refList[i], refList[j] = refList[j], refList[i]
}

package main

import (
	"log"
	"net"
	"net/rpc"
	"os"
	"os/signal"
	"time"

	"github.com/gibheer/pkiadm"
)

const (
	ENoIDGiven      = Error("no ID given")
	EUnknownType    = Error("unknown type found")
	ENotInitialized = Error("resource not initialized")
	ENotFound       = Error("resource not found")
	EWrongType      = Error("incompatible type found - please report error")
	EAlreadyExist   = Error("resource already exists")
)

var (
	NoInterval = Interval{}
)

type (
	Resource interface {
		// Return the unique ResourceName
		Name() pkiadm.ResourceName
		// Refresh must trigger a rebuild of the resource.
		Refresh(*Storage) error
		// RefreshInterval returns the dates and interval settings which are used to
		// decide when to trigger a refresh for the resource.
		RefreshInterval() Interval
		// Return the PEM output of the contained resource.
		Pem() ([]byte, error)
		// Return the checksum of the PEM content.
		Checksum() []byte
		// DependsOn must return the resource names it is depending on.
		DependsOn() []pkiadm.ResourceName
	}

	Interval struct {
		// Created states the time, the resource was created.
		Created time.Time
		// LastRefresh is the time, when the resource was last refreshed.
		LastRefresh time.Time
		// RefreshAfter is the duration after which the refresh of the resource
		// is triggered.
		RefreshAfter time.Duration
		// InvalidAfter is the duration after which this resource becomes invalid.
		// The decision when a resource becomes invalid is based on the created time
		// and the duration. When the refresh duration is less than the invalid
		// duration, then the resource will never be invalid.
		InvalidAfter time.Duration
	}

	Error string
)

func (e Error) Error() string { return string(e) }

func main() {
	os.Exit(_main())
}

func _main() int {
	cfg, err := pkiadm.LoadConfig()
	if err != nil {
		log.Fatalf("could not load config: %s", err)
	}

	addr, err := net.ResolveUnixAddr("unix", cfg.Path)
	if err != nil {
		log.Fatalf("could not parse unix path: %s", err)
	}

	storage, err := NewStorage(cfg.Storage)
	if err != nil {
		log.Fatalf("error when loading: %s\n", err)
	}

	server, err := NewServer(storage)
	if err != nil {
		log.Fatalf("error when loading server: %s\n", err)
	}

	rpcServer := rpc.NewServer()
	if err := rpcServer.RegisterName(pkiadm.ProtoIdent, server); err != nil {
		log.Fatalf("could not bind rpc interface: %s\n", err)
	}

	listener, err := net.ListenUnix("unix", addr)
	if err != nil {
		log.Fatalf("could not open listen socket: %s", err)
	}
	defer os.Remove(cfg.Path)

	// start signal listener
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, os.Kill)
	go func() {
		s := <-sigs
		log.Printf("initializing shutdown because of signal: %s", s)
		listener.Close()
		os.Remove(cfg.Path)
		os.Exit(1)
	}()

	rpcServer.Accept(listener)

	return 0
}

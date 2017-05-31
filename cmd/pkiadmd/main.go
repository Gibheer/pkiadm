package main

import (
	"log"
	"net"
	"net/rpc"
	"os"
	"os/signal"

	"github.com/gibheer/pkiadm"
)

//const (
//	RTPrivateKey ResourceType = iota
//	RTPublicKey
//	RTCSR
//	RTCertificate
//	RTLocation
//	RTSerial
//	RTSubject
//)

const (
	ENoIDGiven      = Error("no ID given")
	EUnknownType    = Error("unknown type found")
	ENotInitialized = Error("resource not initialized")
	ENotFound       = Error("resource not found")
	EWrongType      = Error("incompatible type found - please report error")
	EAlreadyExist   = Error("resource already exists")
)

type (
	Resource interface {
		// Return the unique ResourceName
		Name() pkiadm.ResourceName
		// AddDependency registers a depending resource to be retuened by Dependencies()
		// Refresh must trigger a rebuild of the resource.
		Refresh(*Storage) error
		// Return the PEM output of the contained resource.
		Pem() ([]byte, error)
		Checksum() []byte
		// DependsOn must return the resource names it is depending on.
		DependsOn() []pkiadm.ResourceName
	}

	//	ResourceName struct {
	//		ID   string
	//		Type ResourceType
	//	}

	ResourceType uint

	Error string
)

func (e Error) Error() string { return string(e) }

//func (r ResourceName) String() string { return r.Type.String() + "/" + r.ID }

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

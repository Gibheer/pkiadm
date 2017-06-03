package main

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/gibheer/pkiadm"
)

func main() {
	cfg, err := pkiadm.LoadConfig()
	if err != nil {
		fmt.Printf("could not load config: %s\n", err)
		os.Exit(2)
	}

	client, err := pkiadm.NewClient(*cfg)
	if err != nil {
		fmt.Printf("Could not open connection to server: %s\n", err)
		os.Exit(2)
	}
	defer client.Close()

	if len(os.Args) == 1 {
		printCommands()
		os.Exit(0)
	}

	cmd := os.Args[1]
	args := os.Args[2:]
	switch cmd {
	case `create-subj`:
		err = createSubject(args, client)
	case `delete-subj`:
		err = deleteSubject(args, client)
	case `list-subj`:
		err = listSubject(args, client)
	case `set-subj`:
		err = setSubject(args, client)
	case `show-subj`:
		err = showSubject(args, client)
	case `create-private`:
		err = createPrivateKey(args, client)
	case `delete-private`:
		err = deletePrivateKey(args, client)
	case `list-private`:
		err = listPrivateKey(args, client)
	case `set-private`:
		err = setPrivateKey(args, client)
	case `show-private`:
		err = showPrivateKey(args, client)
	case `create-public`:
		err = createPublicKey(args, client)
	case `delete-public`:
		err = deletePublicKey(args, client)
	case `list-public`:
		err = listPublicKey(args, client)
	case `set-public`:
		err = setPublicKey(args, client)
	case `show-public`:
		err = showPublicKey(args, client)
	case `create-location`:
		err = createLocation(args, client)
	case `delete-location`:
		err = deleteLocation(args, client)
	case `list-location`:
		err = listLocation(args, client)
	case `set-location`:
		err = setLocation(args, client)
	case `show-location`:
		err = showLocation(args, client)
	case `create-csr`:
		err = createCSR(args, client)
	case `delete-csr`:
		err = deleteCSR(args, client)
	case `list-csr`:
		err = listCSR(args, client)
	case `set-csr`:
		err = setCSR(args, client)
	case `show-csr`:
		err = showCSR(args, client)
	default:
		fmt.Printf("unknown subcommand '%s'\n", cmd)
		printCommands()
		os.Exit(0)
	}
	if err != nil {
		fmt.Printf("received an error: %s\n", err)
		os.Exit(1)
	}
}

func printCommands() {
	fmt.Println(`Usage: pkiadm <subcommand> [options]
where subcommand is one of:`)
	out := tabwriter.NewWriter(os.Stdout, 0, 4, 1, ' ', 0)
	fmt.Fprintf(out, "  %s\t%s\n", "def-list", "list all registered definitions")
	fmt.Fprintf(out, "  %s\t%s\n", "create-file", "create a new file export")
	fmt.Fprintf(out, "  %s\t%s\n", "list-files", "list all file exports")
	fmt.Fprintf(out, "  %s\t%s\n", "delete-file", "delete a file export from the database and os")
	fmt.Fprintf(out, "  %s\t%s\n", "create-private-key", "create a new private key")
	fmt.Fprintf(out, "  %s\t%s\n", "list-private-keys", "list all private keys")
	fmt.Fprintf(out, "  %s\t%s\n", "get-private-key", "get information on a specific private key")
	fmt.Fprintf(out, "  %s\t%s\n", "delete-private-key", "delete a specific private key")
	fmt.Fprintf(out, "  %s\t%s\n", "create-public-key", "create a new public key")
	fmt.Fprintf(out, "  %s\t%s\n", "list-public-keys", "list all public keys")
	fmt.Fprintf(out, "  %s\t%s\n", "delete-public-key", "delete a specific public key")
	out.Flush()
}

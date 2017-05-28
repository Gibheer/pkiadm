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
	//	case `list`:
	//		err = listDescription(args, client)
	//	case `create-file`:
	//		err = createFile(args, client)
	//	case `list-files`:
	//		err = listFile(args, client)
	//	case `delete-file`:
	//		err = deleteFile(args, client)
	//	case `create-private-key`:
	//		err = createPrivateKey(args, client)
	//	case `get-private-key`:
	//		err = getPrivateKey(args, client)
	//	case `list-private-keys`:
	//		err = listPrivateKey(args, client)
	//	case `delete-private-key`:
	//		err = deletePrivateKey(args, client)
	//	case `create-public-key`:
	//		err = createPublicKey(args, client)
	//	case `list-public-keys`:
	//		err = listPublicKey(args, client)
	//	case `delete-public-key`:
	//		err = deletePublicKey(args, client)
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

package main

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/gibheer/pkiadm"
	flag "github.com/spf13/pflag"
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
	case `list`:
		err = list(args, client)
	case `create-serial`:
		err = createSerial(args, client)
	case `delete-serial`:
		err = deleteSerial(args, client)
	case `list-serial`:
		err = listSerial(args, client)
	case `set-serial`:
		err = setSerial(args, client)
	case `show-serial`:
		err = showSerial(args, client)
	case `create-ca`:
		err = createCA(args, client)
	case `delete-ca`:
		err = deleteCA(args, client)
	case `list-ca`:
		err = listCA(args, client)
	case `set-ca`:
		err = setCA(args, client)
	case `show-ca`:
		err = showCA(args, client)
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
	case `create-cert`:
		err = createCertificate(args, client)
	case `delete-cert`:
		err = deleteCertificate(args, client)
	case `list-cert`:
		err = listCertificate(args, client)
	case `set-cert`:
		err = setCertificate(args, client)
	case `show-cert`:
		err = showCertificate(args, client)
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
	fmt.Fprintf(out, "  %s\t%s\n", "create-ca", "create a new CA")
	fmt.Fprintf(out, "  %s\t%s\n", "create-cert", "create a new certificate")
	fmt.Fprintf(out, "  %s\t%s\n", "create-csr", "create a new certificate sign request")
	fmt.Fprintf(out, "  %s\t%s\n", "create-location", "create a new file export")
	fmt.Fprintf(out, "  %s\t%s\n", "create-private", "create a new private key")
	fmt.Fprintf(out, "  %s\t%s\n", "create-public", "create a new public key")
	fmt.Fprintf(out, "  %s\t%s\n", "create-serial", "")
	fmt.Fprintf(out, "  %s\t%s\n", "create-subj", "")

	fmt.Fprintf(out, "  %s\t%s\n", "delete-ca", "delete a CA")
	fmt.Fprintf(out, "  %s\t%s\n", "delete-cert", "")
	fmt.Fprintf(out, "  %s\t%s\n", "delete-csr", "")
	fmt.Fprintf(out, "  %s\t%s\n", "delete-location", "")
	fmt.Fprintf(out, "  %s\t%s\n", "delete-private", "")
	fmt.Fprintf(out, "  %s\t%s\n", "delete-public", "")
	fmt.Fprintf(out, "  %s\t%s\n", "delete-serial", "")
	fmt.Fprintf(out, "  %s\t%s\n", "delete-subj", "")

	fmt.Fprintf(out, "  %s\t%s\n", "list", "")
	fmt.Fprintf(out, "  %s\t%s\n", "list-ca", "list all available CAs")
	fmt.Fprintf(out, "  %s\t%s\n", "list-cert", "list all available certificates")
	fmt.Fprintf(out, "  %s\t%s\n", "list-csr", "list all available certificate sign requests")
	fmt.Fprintf(out, "  %s\t%s\n", "list-location", "list all file exports")
	fmt.Fprintf(out, "  %s\t%s\n", "list-private", "list all private keys")
	fmt.Fprintf(out, "  %s\t%s\n", "list-public", "list all public keys")
	fmt.Fprintf(out, "  %s\t%s\n", "list-serial", "")
	fmt.Fprintf(out, "  %s\t%s\n", "list-subj", "")

	fmt.Fprintf(out, "  %s\t%s\n", "set-ca", "change attributes of a CA")
	fmt.Fprintf(out, "  %s\t%s\n", "set-cert", "change attributes of a certificate")
	fmt.Fprintf(out, "  %s\t%s\n", "set-csr", "change attributes of a certificate sign request")
	fmt.Fprintf(out, "  %s\t%s\n", "set-location", "change attributes of a location")
	fmt.Fprintf(out, "  %s\t%s\n", "set-private", "change attributes of a private key")
	fmt.Fprintf(out, "  %s\t%s\n", "set-public", "change attributes of a public key")
	fmt.Fprintf(out, "  %s\t%s\n", "set-serial", "")
	fmt.Fprintf(out, "  %s\t%s\n", "set-subj", "")

	fmt.Fprintf(out, "  %s\t%s\n", "show-ca", "")
	fmt.Fprintf(out, "  %s\t%s\n", "show-cert", "")
	fmt.Fprintf(out, "  %s\t%s\n", "show-csr", "")
	fmt.Fprintf(out, "  %s\t%s\n", "show-location", "")
	fmt.Fprintf(out, "  %s\t%s\n", "show-private", "")
	fmt.Fprintf(out, "  %s\t%s\n", "show-public", "")
	fmt.Fprintf(out, "  %s\t%s\n", "show-serial", "")
	fmt.Fprintf(out, "  %s\t%s\n", "show-subj", "")

	out.Flush()
}

func list(args []string, c *pkiadm.Client) error {
	fs := flag.NewFlagSet("pkiadm list", flag.ExitOnError)
	fs.Parse(args)

	resources, err := c.List()
	if err != nil {
		return err
	}
	out := tabwriter.NewWriter(os.Stdout, 0, 4, 1, ' ', 0)
	fmt.Fprintf(out, "%s\t%s\t\n", "type", "id")
	for _, res := range resources {
		fmt.Fprintf(out, "%s\t%s\t\n", res.Type, res.ID)
	}
	out.Flush()
	return nil
}

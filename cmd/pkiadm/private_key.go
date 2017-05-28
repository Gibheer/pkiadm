package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/gibheer/pkiadm"
	"github.com/pkg/errors"
	flag "github.com/spf13/pflag"
)

func createPrivateKey(args []string, client *pkiadm.Client) error {
	fs := flag.NewFlagSet("create-private", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Printf("Usage of %s:\n", "pkiadm create-private")
		fmt.Println(`
Create a new private key for different use cases. The supported types are rsa,
ecdsa and ed25519. Please keep in mind, that ed25519 is currently not supported
for certificate generation.
`)
		fs.PrintDefaults()
	}
	pk := pkiadm.PrivateKey{}
	fs.StringVar(&pk.ID, "id", "", "set the unique id for the new private key")
	var pkType = fs.String("type", "rsa", "set the type of the private key (rsa, ecdsa, ed25519)")
	fs.UintVar(&pk.Bits, "bits", 2048, "set the number of bits to use. For rsa it can be 1024 up to 32768, for ecdsa 224, 256, 384, 521. Ed25519 is set to 256 by default.")
	fs.Parse(args)

	pkT, err := pkiadm.StringToPrivateKeyType(*pkType)
	if err != nil {
		return err
	}
	pk.Type = pkT
	if err := client.CreatePrivateKey(pk); err != nil {
		return errors.Wrap(err, "could not create private key")
	}

	return nil
}
func setPrivateKey(args []string, client *pkiadm.Client) error {
	fs := flag.NewFlagSet("set-private", flag.ExitOnError)
	pk := pkiadm.PrivateKey{}
	fs.StringVar(&pk.ID, "id", "", "set the id of the private key to change")
	var pkType = fs.String("type", "rsa", "set the type of the private key (rsa, ecdsa, ed25519)")
	fs.UintVar(&pk.Bits, "bits", 2048, "set the number of bits to use. For rsa it can be 1024 up to 32768, for ecdsa 224, 256, 384, 521. Ed25519 is set to 256 by default.")
	fs.Parse(args)

	pkT, err := pkiadm.StringToPrivateKeyType(*pkType)
	if err != nil {
		return err
	}
	pk.Type = pkT

	fieldList := []string{}
	for _, field := range []string{"type", "bits"} {
		flag := fs.Lookup(field)
		if flag.Changed {
			fieldList = append(fieldList, field)
		}
	}

	if err := client.SetPrivateKey(pk, fieldList); err != nil {
		return err
	}
	return nil
}
func deletePrivateKey(args []string, client *pkiadm.Client) error {
	fs := flag.NewFlagSet("delete-private", flag.ExitOnError)
	var id = fs.String("id", "", "set the id of the private key to delete")
	fs.Parse(args)

	if err := client.DeletePrivateKey(*id); err != nil {
		return err
	}
	return nil
}
func listPrivateKey(args []string, client *pkiadm.Client) error {
	fs := flag.NewFlagSet("list-private", flag.ExitOnError)
	fs.Parse(args)

	pks, err := client.ListPrivateKey()
	if err != nil {
		return err
	}

	if len(pks) == 0 {
		return nil
	}
	out := tabwriter.NewWriter(os.Stdout, 2, 2, 1, ' ', tabwriter.AlignRight)
	fmt.Fprintf(out, "%s\t%s\t%s\t\n", "id", "type", "bits")
	for _, pk := range pks {
		fmt.Fprintf(out, "%s\t%s\t%d\t\n", pk.ID, pk.Type.String(), pk.Bits)
	}
	out.Flush()

	return nil
}
func showPrivateKey(args []string, client *pkiadm.Client) error {
	fs := flag.NewFlagSet("show-private", flag.ExitOnError)
	var id = fs.String("id", "", "set the id of the private key to show")
	fs.Parse(args)

	pk, err := client.ShowPrivateKey(*id)
	if err != nil {
		return err
	}
	out := tabwriter.NewWriter(os.Stdout, 2, 2, 1, ' ', tabwriter.AlignRight)
	fmt.Fprintf(out, "ID:\t%s\t\n", pk.ID)
	fmt.Fprintf(out, "type:\t%s\t\n", pk.Type.String())
	fmt.Fprintf(out, "bits:\t%d\t\n", pk.Bits)
	fmt.Fprintf(out, "checksum:\t%s\t\n", base64.StdEncoding.EncodeToString(pk.Checksum))
	out.Flush()
	return nil
}

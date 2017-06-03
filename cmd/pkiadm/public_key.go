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

func createPublicKey(args []string, client *pkiadm.Client) error {
	fs := flag.NewFlagSet("pkiadm create-public", flag.ExitOnError)
	id := fs.String("id", "", "the id to set for the public key")
	pk := fs.String("private-key", "", "the id of the private key to use for public key creation")
	fs.Parse(args)

	pkName := pkiadm.ResourceName{ID: *pk, Type: pkiadm.RTPrivateKey}
	if err := client.CreatePublicKey(
		pkiadm.PublicKey{ID: *id, PrivateKey: pkName},
	); err != nil {
		return errors.Wrap(err, "Could not create public key")
	}
	return nil
}
func setPublicKey(args []string, client *pkiadm.Client) error {
	fs := flag.NewFlagSet("pkiadm set-public", flag.ExitOnError)
	id := fs.String("id", "", "the id of the public key to change")
	pk := fs.String("private-key", "", "the id of the new private key to use for public key generation")
	fs.Parse(args)

	if !fs.Lookup("private-key").Changed {
		return nil
	}
	pkName := pkiadm.ResourceName{ID: *pk, Type: pkiadm.RTPrivateKey}
	if err := client.SetPublicKey(
		pkiadm.PublicKey{ID: *id, PrivateKey: pkName},
		[]string{"private-key"},
	); err != nil {
		return errors.Wrap(err, "Could not change public key")
	}
	return nil
}
func deletePublicKey(args []string, client *pkiadm.Client) error {
	fs := flag.NewFlagSet("pkiadm delete-public", flag.ExitOnError)
	id := fs.String("id", "", "the id of the public key to delete")
	fs.Parse(args)

	if err := client.DeletePublicKey(pkiadm.PublicKey{ID: *id}); err != nil {
		return errors.Wrap(err, "Could not delete public key")
	}
	return nil
}
func listPublicKey(args []string, client *pkiadm.Client) error {
	fs := flag.NewFlagSet("list-private", flag.ExitOnError)
	fs.Parse(args)

	pubs, err := client.ListPublicKey()
	if err != nil {
		return err
	}

	if len(pubs) == 0 {
		return nil
	}
	out := tabwriter.NewWriter(os.Stdout, 2, 2, 1, ' ', tabwriter.AlignRight)
	fmt.Fprintf(out, "%s\t%s\t%s\t\n", "id", "type", "private-key")
	for _, pub := range pubs {
		fmt.Fprintf(out, "%s\t%s\t%s\t\n", pub.ID, pub.Type.String(), pub.PrivateKey)
	}
	out.Flush()

	return nil
}
func showPublicKey(args []string, client *pkiadm.Client) error {
	fs := flag.NewFlagSet("show-private", flag.ExitOnError)
	var id = fs.String("id", "", "set the id of the private key to show")
	fs.Parse(args)

	pub, err := client.ShowPublicKey(*id)
	if err != nil {
		return err
	}
	out := tabwriter.NewWriter(os.Stdout, 2, 2, 1, ' ', tabwriter.AlignRight)
	fmt.Fprintf(out, "ID:\t%s\t\n", pub.ID)
	fmt.Fprintf(out, "type:\t%s\t\n", pub.Type.String())
	fmt.Fprintf(out, "private:\t%s\t\n", pub.PrivateKey)
	fmt.Fprintf(out, "checksum:\t%s\t\n", base64.StdEncoding.EncodeToString(pub.Checksum))
	out.Flush()
	return nil
}

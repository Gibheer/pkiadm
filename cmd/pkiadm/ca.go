package main

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/gibheer/pkiadm"
	"github.com/pkg/errors"
	flag "github.com/spf13/pflag"
)

func createCA(args []string, client *pkiadm.Client) error {
	fs := flag.NewFlagSet("pkiadm create-public", flag.ExitOnError)
	id := fs.String("id", "", "the id to set for the CA")
	ct := fs.String("type", "local", "the type of CA to create (local, LetsEncrypt)")
	cert := fs.String("certificate", "", "the id of the certificate to use for CA creation")
	fs.Parse(args)

	caType := pkiadm.StringToCAType(*ct)
	if caType == pkiadm.CAUnknown {
		return errors.New("unknown ca type")
	}
	caName := pkiadm.ResourceName{ID: *cert, Type: pkiadm.RTCertificate}
	if err := client.CreateCA(
		pkiadm.CA{ID: *id, Type: caType, Certificate: caName},
	); err != nil {
		return errors.Wrap(err, "Could not create CA")
	}
	return nil
}
func setCA(args []string, client *pkiadm.Client) error {
	fs := flag.NewFlagSet("pkiadm set-public", flag.ExitOnError)
	id := fs.String("id", "", "the id of the CA to change")
	ct := fs.String("type", "local", "the type of CA to create (local, LetsEncrypt)")
	cert := fs.String("certificate", "", "the id of the certificate to use for signing")
	fs.Parse(args)

	fieldList := []string{}
	for _, field := range []string{"certificate", "type"} {
		flag := fs.Lookup(field)
		if flag.Changed {
			fieldList = append(fieldList, field)
		}
	}
	caType := pkiadm.StringToCAType(*ct)
	if caType == pkiadm.CAUnknown {
		return errors.New("unknown ca type")
	}
	caName := pkiadm.ResourceName{ID: *cert, Type: pkiadm.RTCertificate}
	if err := client.SetCA(
		pkiadm.CA{ID: *id, Certificate: caName},
		fieldList,
	); err != nil {
		return errors.Wrap(err, "Could not change CA")
	}
	return nil
}
func deleteCA(args []string, client *pkiadm.Client) error {
	fs := flag.NewFlagSet("pkiadm delete-public", flag.ExitOnError)
	id := fs.String("id", "", "the id of the CA to delete")
	fs.Parse(args)

	if err := client.DeleteCA(*id); err != nil {
		return errors.Wrap(err, "Could not delete CA")
	}
	return nil
}
func listCA(args []string, client *pkiadm.Client) error {
	fs := flag.NewFlagSet("list-private", flag.ExitOnError)
	fs.Parse(args)

	cas, err := client.ListCA()
	if err != nil {
		return err
	}

	if len(cas) == 0 {
		return nil
	}
	out := tabwriter.NewWriter(os.Stdout, 2, 2, 1, ' ', tabwriter.AlignRight)
	fmt.Fprintf(out, "%s\t%s\t%s\t\n", "id", "type", "certificate")
	for _, ca := range cas {
		fmt.Fprintf(out, "%s\t%s\t%s\t\n", ca.ID, ca.Type.String(), ca.Certificate.ID)
	}
	out.Flush()

	return nil
}
func showCA(args []string, client *pkiadm.Client) error {
	fs := flag.NewFlagSet("show-private", flag.ExitOnError)
	var id = fs.String("id", "", "set the id of the private key to show")
	fs.Parse(args)

	ca, err := client.ShowCA(*id)
	if err != nil {
		return err
	}
	out := tabwriter.NewWriter(os.Stdout, 2, 2, 1, ' ', tabwriter.AlignRight)
	fmt.Fprintf(out, "ID:\t%s\t\n", ca.ID)
	fmt.Fprintf(out, "type:\t%s\t\n", ca.Type.String())
	fmt.Fprintf(out, "certificate:\t%s\t\n", ca.Certificate.ID)
	out.Flush()
	return nil
}

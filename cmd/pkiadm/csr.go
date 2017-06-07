package main

import (
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/gibheer/pkiadm"
	"github.com/pkg/errors"
	flag "github.com/spf13/pflag"
)

func createCSR(args []string, client *pkiadm.Client) error {
	fs := flag.NewFlagSet("create-csr", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Printf("Usage of %s:\n", "pkiadm create-csr")
		fmt.Println(`
Create a new certificate sign request. This request can be signed by a CA to create a new certificate.
FQDNs, mail addresses and ips can be set multiple times or once as a comma separated list.
`)
		fs.PrintDefaults()
	}
	csr := pkiadm.CSR{}
	fs.StringVar(&csr.ID, "id", "", "set the unique id for the new private key")
	parseCSRArgs(fs, args, &csr)

	if err := client.CreateCSR(csr); err != nil {
		return errors.Wrap(err, "could not create private key")
	}

	return nil
}
func setCSR(args []string, client *pkiadm.Client) error {
	fs := flag.NewFlagSet("set-csr", flag.ExitOnError)
	csr := pkiadm.CSR{}
	fs.StringVar(&csr.ID, "id", "", "set the id of the CSR to adjust")
	parseCSRArgs(fs, args, &csr)

	fieldList := []string{}
	for _, field := range []string{"private-key", "subject", "ip", "fqdn", "mail"} {
		flag := fs.Lookup(field)
		if flag.Changed {
			fieldList = append(fieldList, field)
		}
	}

	if err := client.SetCSR(csr, fieldList); err != nil {
		return err
	}
	return nil
}
func parseCSRArgs(fs *flag.FlagSet, args []string, csr *pkiadm.CSR) {
	fs.StringSliceVar(&csr.DNSNames, "fqdn", []string{}, "assign the FQDNs")
	fs.StringSliceVar(&csr.EmailAddresses, "mail", []string{}, "assign the mail addresses")
	fs.IPSliceVar(&csr.IPAddresses, "ip", []net.IP{}, "assign the ips")
	pk := fs.String("private-key", "", "set the id of the private key to sign the request")
	subject := fs.String("subject", "", "set the id of the subject to use for this request")
	fs.Parse(args)

	csr.PrivateKey = pkiadm.ResourceName{*pk, pkiadm.RTPrivateKey}
	csr.Subject = pkiadm.ResourceName{*subject, pkiadm.RTSubject}
}

func deleteCSR(args []string, client *pkiadm.Client) error {
	fs := flag.NewFlagSet("delete-csr", flag.ExitOnError)
	var id = fs.String("id", "", "set the id of the csr to delete")
	fs.Parse(args)

	if err := client.DeleteCSR(*id); err != nil {
		return err
	}
	return nil
}
func listCSR(args []string, client *pkiadm.Client) error {
	fs := flag.NewFlagSet("list-csr", flag.ExitOnError)
	fs.Parse(args)

	csrs, err := client.ListCSR()
	if err != nil {
		return err
	}

	if len(csrs) == 0 {
		return nil
	}
	out := tabwriter.NewWriter(os.Stdout, 2, 2, 1, ' ', tabwriter.AlignRight)
	fmt.Fprintf(out, "%s\t%s\t%s\t%s\t%s\t%s\t\n", "id", "private-key", "subject", "names", "ips", "mails")
	for _, csr := range csrs {
		fmt.Fprintf(
			out,
			"%s\t%s\t%s\t%d\t%d\t%d\t\n",
			csr.ID,
			csr.PrivateKey.ID,
			csr.Subject.ID,
			len(csr.DNSNames),
			len(csr.IPAddresses),
			len(csr.EmailAddresses),
		)
	}
	out.Flush()

	return nil
}
func showCSR(args []string, client *pkiadm.Client) error {
	fs := flag.NewFlagSet("show-private", flag.ExitOnError)
	var id = fs.String("id", "", "set the id of the private key to show")
	fs.Parse(args)

	csr, err := client.ShowCSR(*id)
	if err != nil {
		return err
	}
	ips := []string{}
	for _, ip := range csr.IPAddresses {
		ips = append(ips, ip.String())
	}
	out := tabwriter.NewWriter(os.Stdout, 2, 2, 1, ' ', tabwriter.AlignRight)
	fmt.Fprintf(out, "ID:\t%s\t\n", csr.ID)
	fmt.Fprintf(out, "private:\t%s\t\n", csr.PrivateKey.ID)
	fmt.Fprintf(out, "subject:\t%s\t\n", csr.Subject.ID)
	fmt.Fprintf(out, "fqdn:\t%s\t\n", ReplaceEmpty(strings.Join(csr.DNSNames, ", ")))
	fmt.Fprintf(out, "ip:\t%s\t\n", ReplaceEmpty(strings.Join(ips, ", ")))
	fmt.Fprintf(out, "mail:\t%s\t\n", ReplaceEmpty(strings.Join(csr.EmailAddresses, ", ")))
	fmt.Fprintf(out, "checksum:\t%s\t\n", base64.StdEncoding.EncodeToString(csr.Checksum))
	out.Flush()
	return nil
}

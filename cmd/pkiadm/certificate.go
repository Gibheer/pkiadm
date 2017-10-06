package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/gibheer/pkiadm"
	"github.com/pkg/errors"
	flag "github.com/spf13/pflag"
)

func createCertificate(args []string, client *pkiadm.Client) error {
	fs := flag.NewFlagSet("create-cert", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Printf("Usage of %s:\n", "pkiadm create-cert")
		fmt.Println(`
This command creates a new certificate and signes it with the provided CA. If you want to buid your own CA, add the self-sign option and leave the ca option blank.
`)
		fs.PrintDefaults()
	}
	cert := pkiadm.Certificate{}
	fs.StringVar(&cert.ID, "id", "", "set the unique id for the new certificate")
	parseCertificateArgs(fs, args, &cert)

	if err := client.CreateCertificate(cert); err != nil {
		return errors.Wrap(err, "could not create certificate")
	}

	return nil
}
func setCertificate(args []string, client *pkiadm.Client) error {
	fs := flag.NewFlagSet("set-cert", flag.ExitOnError)
	cert := pkiadm.Certificate{}
	fs.StringVar(&cert.ID, "id", "", "set the id of the certificate to change")
	parseCertificateArgs(fs, args, &cert)

	fieldList := []string{}
	for _, field := range []string{"private", "csr", "ca", "serial", "duration", "self-sign"} {
		flag := fs.Lookup(field)
		if flag.Changed {
			fieldList = append(fieldList, field)
		}
	}

	if err := client.SetCertificate(cert, fieldList); err != nil {
		return err
	}
	return nil
}
func parseCertificateArgs(fs *flag.FlagSet, args []string, cert *pkiadm.Certificate) {
	pk := fs.String("private", "", "the private key id to sign the certificate sign request")
	csr := fs.String("csr", "", "the CSR to sign to get the resulting certificate")
	ca := fs.String("ca", "", "the certificate to use to sign the certificate sign request")
	serial := fs.String("serial", "", "the serial generator used to fetch a serial")
	fs.DurationVar(&cert.Duration, "duration", 360*24*time.Hour, "the time the certificate is valid (in h, m, s)") // these are 360 days
	fs.BoolVar(&cert.IsCA, "self-sign", false, "set this to true to create a self signed certificate (for CA usage)")
	fs.Parse(args)

	cert.PrivateKey = pkiadm.ResourceName{*pk, pkiadm.RTPrivateKey}
	cert.CSR = pkiadm.ResourceName{*csr, pkiadm.RTCSR}
	cert.CA = pkiadm.ResourceName{*ca, pkiadm.RTCA}
	cert.Serial = pkiadm.ResourceName{*serial, pkiadm.RTSerial}
}

func deleteCertificate(args []string, client *pkiadm.Client) error {
	fs := flag.NewFlagSet("delete-cert", flag.ExitOnError)
	var id = fs.String("id", "", "set the id of the private key to delete")
	fs.Parse(args)

	if err := client.DeleteCertificate(*id); err != nil {
		return err
	}
	return nil
}
func listCertificate(args []string, client *pkiadm.Client) error {
	fs := flag.NewFlagSet("list-cert", flag.ExitOnError)
	fs.Parse(args)

	certs, err := client.ListCertificate()
	if err != nil {
		return err
	}

	if len(certs) == 0 {
		return nil
	}
	out := tabwriter.NewWriter(os.Stdout, 2, 2, 1, ' ', tabwriter.AlignRight)
	fmt.Fprintf(out, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t\n", "id", "private", "csr", "ca", "serial", "created", "duration", "self-signed")
	for _, cert := range certs {
		fmt.Fprintf(out, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%t\t\n", cert.ID, cert.PrivateKey.ID, cert.CSR.ID, cert.CA.ID, cert.Serial.ID, cert.Created, cert.Duration, cert.IsCA)
	}
	out.Flush()

	return nil
}
func showCertificate(args []string, client *pkiadm.Client) error {
	fs := flag.NewFlagSet("show-cert", flag.ExitOnError)
	var id = fs.String("id", "", "set the id of the private key to show")
	fs.Parse(args)

	cert, err := client.ShowCertificate(*id)
	if err != nil {
		return err
	}
	out := tabwriter.NewWriter(os.Stdout, 2, 2, 1, ' ', tabwriter.AlignRight)
	fmt.Fprintf(out, "id:\t%s\n", cert.ID)
	fmt.Fprintf(out, "private:\t%s\n", cert.PrivateKey.ID)
	fmt.Fprintf(out, "csr:\t%s\n", cert.CSR.ID)
	fmt.Fprintf(out, "ca:\t%s\n", cert.CA.ID)
	fmt.Fprintf(out, "serial:\t%s\n", cert.Serial.ID)
	fmt.Fprintf(out, "created:\t%s\n", cert.Created)
	fmt.Fprintf(out, "duration:\t%s\n", cert.Duration)
	fmt.Fprintf(out, "self-signed:\t%t\n", cert.IsCA)
	fmt.Fprintf(out, "checksum:\t%s\n", base64.StdEncoding.EncodeToString(cert.Checksum))
	out.Flush()
	return nil
}

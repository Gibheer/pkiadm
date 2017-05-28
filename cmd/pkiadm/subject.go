package main

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/gibheer/pkiadm"
	"github.com/pkg/errors"
	flag "github.com/spf13/pflag"
)

func createSubject(args []string, client *pkiadm.Client) error {
	fs := flag.NewFlagSet("pkiadm create-subj", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Printf("Usage of %s:\n", "pkiadm create-subj")
		fmt.Println(`
Create a new subject which can then be used in the CSR. All fields
are optional and can be provided multiple times to add multiple instances.
In most cases only the common name, organization name and the country is provided.
`)
		fs.PrintDefaults()
	}
	subj := pkiadm.Subject{}
	fs.StringVar(&subj.ID, "id", "", "the unique subject id")
	setSubjectParams(&subj, fs)
	fs.Parse(args)

	if subj.ID == "" {
		return errors.New("no ID given")
	}

	if err := client.CreateSubject(subj); err != nil {
		fmt.Println("got an error")
		return errors.Wrap(err, "could not create new subject")
	}
	return nil
}

func setSubject(args []string, client *pkiadm.Client) error {
	fs := flag.NewFlagSet("pkiadm set-subjprop", flag.ExitOnError)
	subj := pkiadm.Subject{}
	fs.StringVar(&subj.ID, "id", "", "set the ID to edit")
	setSubjectParams(&subj, fs)
	fs.Parse(args)

	fieldList := []string{}
	for _, field := range []string{"common-name", "org", "org-unit", "locality", "province", "street", "code"} {
		flag := fs.Lookup(field)
		if flag.Changed {
			fieldList = append(fieldList, field)
		}
	}

	if err := client.SetSubject(subj, fieldList); err != nil {
		return err
	}
	return nil
}

func deleteSubject(args []string, client *pkiadm.Client) error {
	fs := flag.NewFlagSet("pkiadm delete-subj", flag.ExitOnError)
	var (
		id = fs.String("id", "", "the id to delete")
	)
	fs.Parse(args)

	if err := client.DeleteSubject(*id); err != nil {
		return err
	}
	return nil
}

func listSubject(args []string, client *pkiadm.Client) error {
	fs := flag.NewFlagSet("pkiadm list-subj", flag.ExitOnError)
	fs.Parse(args)

	res, err := client.ListSubject()
	if err != nil {
		return err
	}

	if len(res) == 0 {
		return nil
	}
	out := tabwriter.NewWriter(os.Stdout, 2, 2, 1, ' ', 0)
	fmt.Fprintf(out, "ID\tserial\tcommon name\torganization\torg-unit\tlocality\tprovince\tstreet\tpostal\n")
	for _, subj := range res {
		fmt.Fprintf(
			out,
			"%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			subj.ID,
			ReplaceEmpty(subj.Name.SerialNumber),
			ReplaceEmpty(subj.Name.CommonName),
			ReplaceEmpty(strings.Join(subj.Name.Organization, ", ")),
			ReplaceEmpty(strings.Join(subj.Name.OrganizationalUnit, ", ")),
			ReplaceEmpty(strings.Join(subj.Name.Locality, ", ")),
			ReplaceEmpty(strings.Join(subj.Name.Province, ", ")),
			ReplaceEmpty(strings.Join(subj.Name.StreetAddress, ", ")),
			ReplaceEmpty(strings.Join(subj.Name.PostalCode, ", ")),
		)
	}
	out.Flush()
	return nil
}

// ShowSubject prints all fields of a subject.
func showSubject(args []string, client *pkiadm.Client) error {
	fs := flag.NewFlagSet("pkiadm show-subj", flag.ExitOnError)
	var (
		id = fs.String("id", "", "the identifier of the subject to show")
	)
	fs.Parse(args)

	subj, err := client.ShowSubject(*id)
	if err != nil {
		return err
	}
	out := tabwriter.NewWriter(os.Stdout, 2, 2, 1, ' ', tabwriter.AlignRight)
	fmt.Fprintf(out, "ID:\t%s\t\n", subj.ID)
	fmt.Fprintf(out, "serial:\t%s\t\n", ReplaceEmpty(subj.Name.SerialNumber))
	fmt.Fprintf(out, "common name:\t%s\t\n", ReplaceEmpty(subj.Name.CommonName))
	fmt.Fprintf(out, "organization:\t%s\t\n", ReplaceEmpty(strings.Join(subj.Name.Organization, ", ")))
	fmt.Fprintf(out, "org-unit:\t%s\t\n", ReplaceEmpty(strings.Join(subj.Name.OrganizationalUnit, ", ")))
	fmt.Fprintf(out, "locality:\t%s\t\n", ReplaceEmpty(strings.Join(subj.Name.Locality, ", ")))
	fmt.Fprintf(out, "province:\t%s\t\n", ReplaceEmpty(strings.Join(subj.Name.Province, ", ")))
	fmt.Fprintf(out, "street:\t%s\t\n", ReplaceEmpty(strings.Join(subj.Name.StreetAddress, ", ")))
	fmt.Fprintf(out, "postal code:\t%s\t\n", ReplaceEmpty(strings.Join(subj.Name.PostalCode, ", ")))
	out.Flush()
	return nil
}

// ReplaceEmpty replaces an empty string with a dash sign to visually show, that
// the field is empty and not an empty string.
func ReplaceEmpty(in string) string {
	if in != "" {
		return in
	}
	return "-"
}

// SetSubject adds the common flags for createSubject and setSubject.
func setSubjectParams(subj *pkiadm.Subject, fs *flag.FlagSet) {
	fs.StringVar(&subj.Name.SerialNumber, "serial", "", "set a serial number for the subject")
	fs.StringVar(&subj.Name.CommonName, "common-name", "", "set a unique and human understandable identifier for the subject")
	fs.StringSliceVar(&subj.Name.Country, "country", []string{}, "set countries as short codes or long names")
	fs.StringSliceVar(&subj.Name.Organization, "org", []string{}, "set the organization names")
	fs.StringSliceVar(&subj.Name.OrganizationalUnit, "org-unit", []string{}, "set the sub division or organizational units")
	fs.StringSliceVar(&subj.Name.Locality, "locality", []string{}, "set the city where the organization is located")
	fs.StringSliceVar(&subj.Name.Province, "province", []string{}, "set the province, region or state of the organization")
	fs.StringSliceVar(&subj.Name.StreetAddress, "street", []string{}, "set the street for the organization")
	fs.StringSliceVar(&subj.Name.PostalCode, "code", []string{}, "set the postal code for the address")
}

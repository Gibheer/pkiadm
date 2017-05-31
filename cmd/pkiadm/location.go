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

func createLocation(args []string, client *pkiadm.Client) error {
	fs := flag.NewFlagSet("pkiadm create-location", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Printf("Usage of %s:\n", "pkiadm create-location")
		fmt.Println(`
Create a new file containing the referenced resources, which will be converted to pem format.
The pre command will be run before writing the file and the post command will be run after the file is written.
Resource names are defined as "type/id", where type is one of private, public, csr or cert.
`)
		fs.PrintDefaults()
	}
	loc := pkiadm.Location{}
	fs.StringVar(&loc.ID, "id", "", "the ID of the location to modify")
	if err := parseLocationArgs(&loc, fs, args); err != nil {
		return err
	}
	if err := client.CreateLocation(loc); err != nil {
		return errors.Wrap(err, "could not create new location")
	}
	return nil
}

func setLocation(args []string, client *pkiadm.Client) error {
	fs := flag.NewFlagSet("pkiadm set-location", flag.ExitOnError)
	loc := pkiadm.Location{}
	fs.StringVar(&loc.ID, "id", "", "the ID of the location to modify")
	if err := parseLocationArgs(&loc, fs, args); err != nil {
		return err
	}
	fieldList := []string{}
	for _, field := range []string{"path", "pre-cmd", "post-cmd", "resources"} {
		flag := fs.Lookup(field)
		if flag.Changed {
			fieldList = append(fieldList, field)
		}
	}
	if err := client.SetLocation(loc, fieldList); err != nil {
		return errors.Wrap(err, "could not change location")
	}
	return nil
}

func parseLocationArgs(loc *pkiadm.Location, fs *flag.FlagSet, args []string) error {
	resources := []string{}
	fs.StringVar(&loc.Path, "path", "", "the filename of the location where replaces will be placed")
	fs.StringSliceVar(&resources, "resources", []string{}, "the resource description to add to the location")
	fs.StringVar(&loc.PreCommand, "pre-cmd", "", "the pre command to run before writing the file")
	fs.StringVar(&loc.PostCommand, "post-cmd", "", "the oste command to run after writing the file")
	fs.Parse(args)

	for _, res := range resources {
		parts := strings.Split(res, "/")
		if len(parts) != 2 {
			return errors.Errorf("could not parse resource: '%s'\n", res)
		}
		resType, err := pkiadm.StringToResourceType(parts[0])
		if err != nil {
			return errors.Errorf("invalid resource type '%s'", parts[0])
		}
		loc.Dependencies = append(loc.Dependencies, pkiadm.ResourceName{parts[1], resType})
	}
	return nil
}

func deleteLocation(args []string, client *pkiadm.Client) error {
	fs := flag.NewFlagSet("pkiadm delete-location", flag.ExitOnError)
	id := fs.String("id", "", "the id of the location to delete")
	fs.Parse(args)

	if err := client.DeleteLocation(*id); err != nil {
		return errors.Wrap(err, "could not remove location")
	}
	return nil
}

func showLocation(args []string, client *pkiadm.Client) error {
	fs := flag.NewFlagSet("pkiadm show-location", flag.ExitOnError)
	id := fs.String("id", "", "the id to view in detail")
	fs.Parse(args)

	loc, err := client.ShowLocation(*id)
	if err != nil {
		return err
	}
	deps := []string{}
	for _, dep := range loc.Dependencies {
		deps = append(deps, dep.String())
	}
	out := tabwriter.NewWriter(os.Stdout, 2, 2, 1, ' ', tabwriter.AlignRight)
	fmt.Fprintf(out, "ID:\t%s\t\n", loc.ID)
	fmt.Fprintf(out, "path:\t%s\t\n", loc.Path)
	fmt.Fprintf(out, "pre-cmd:\t%s\t\n", ReplaceEmpty(loc.PreCommand))
	fmt.Fprintf(out, "post-cmd:\t%s\t\n", ReplaceEmpty(loc.PostCommand))
	fmt.Fprintf(out, "deps:\t%s\t\n", strings.Join(deps, ", "))
	out.Flush()
	return nil
}

func listLocation(args []string, client *pkiadm.Client) error {
	fs := flag.NewFlagSet("pkiadm list-location", flag.ExitOnError)
	fs.Parse(args)

	locs, err := client.ListLocation()
	if err != nil {
		return err
	}
	if len(locs) == 0 {
		return nil
	}
	out := tabwriter.NewWriter(os.Stdout, 2, 2, 1, ' ', tabwriter.AlignRight)
	fmt.Fprintf(out, "%s\t%s\t%s\t\n", "id", "path", "deps")
	for _, loc := range locs {
		fmt.Fprintf(out, "%s\t%s\t%d\t\n", loc.ID, loc.Path, len(loc.Dependencies))
	}
	out.Flush()
	return nil
}

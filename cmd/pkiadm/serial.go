package main

import (
	"fmt"
	"math"
	"os"
	"text/tabwriter"

	"github.com/gibheer/pkiadm"
	"github.com/pkg/errors"
	flag "github.com/spf13/pflag"
)

func createSerial(args []string, client *pkiadm.Client) error {
	fs := flag.NewFlagSet("create-private", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Printf("Usage of %s:\n", "pkiadm create-private")
		fmt.Println(`Create a new serial producer for certificate generation. New IDs will be generated by random in the defined limits.`)
		fs.PrintDefaults()
	}
	ser := pkiadm.Serial{}
	fs.StringVar(&ser.ID, "id", "", "set the unique id for the new serial")
	fs.Int64Var(&ser.Min, "min", 0, "set the minimum id")
	fs.Int64Var(&ser.Max, "max", math.MaxInt64, "set the maximum id")
	fs.Parse(args)

	if err := client.CreateSerial(ser); err != nil {
		return errors.Wrap(err, "could not create serial")
	}

	return nil
}
func setSerial(args []string, client *pkiadm.Client) error {
	fs := flag.NewFlagSet("set-private", flag.ExitOnError)
	ser := pkiadm.Serial{}
	fs.StringVar(&ser.ID, "id", "", "set the unique id for the serial to change")
	fs.Int64Var(&ser.Min, "min", 0, "set the minimum id")
	fs.Int64Var(&ser.Max, "max", math.MaxInt64, "set the maximum id")
	fs.Parse(args)

	fieldList := []string{}
	for _, field := range []string{"type", "bits"} {
		flag := fs.Lookup(field)
		if flag.Changed {
			fieldList = append(fieldList, field)
		}
	}

	if err := client.SetSerial(ser, fieldList); err != nil {
		return err
	}
	return nil
}
func deleteSerial(args []string, client *pkiadm.Client) error {
	fs := flag.NewFlagSet("delete-private", flag.ExitOnError)
	var id = fs.String("id", "", "set the id of the serial to delete")
	fs.Parse(args)

	if err := client.DeleteSerial(*id); err != nil {
		return err
	}
	return nil
}
func listSerial(args []string, client *pkiadm.Client) error {
	fs := flag.NewFlagSet("list-private", flag.ExitOnError)
	fs.Parse(args)

	sers, err := client.ListSerial()
	if err != nil {
		return err
	}

	if len(sers) == 0 {
		return nil
	}
	out := tabwriter.NewWriter(os.Stdout, 2, 2, 1, ' ', tabwriter.AlignRight)
	fmt.Fprintf(out, "%s\t%s\t%s\t\n", "id", "min", "max")
	for _, ser := range sers {
		fmt.Fprintf(out, "%s\t%d\t%d\t\n", ser.ID, ser.Min, ser.Max)
	}
	out.Flush()

	return nil
}
func showSerial(args []string, client *pkiadm.Client) error {
	fs := flag.NewFlagSet("show-private", flag.ExitOnError)
	var id = fs.String("id", "", "set the id of the serial to show")
	fs.Parse(args)

	ser, err := client.ShowSerial(*id)
	if err != nil {
		return err
	}
	out := tabwriter.NewWriter(os.Stdout, 2, 2, 1, ' ', tabwriter.AlignRight)
	fmt.Fprintf(out, "ID:\t%s\t\n", ser.ID)
	fmt.Fprintf(out, "min:\t%d\t\n", ser.Min)
	fmt.Fprintf(out, "max:\t%d\t\n", ser.Max)
	out.Flush()
	return nil
}

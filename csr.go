package pkiadm

import (
	"net"
)

type (
	CSR struct {
		// ID is the unique identifier of the CSR.
		ID string

		// The following options are used to generate the content of the CSR.
		DNSNames       []string
		EmailAddresses []string
		IPAddresses    []net.IP

		// PrivateKey is needed to sign the certificate sign request.
		PrivateKey ResourceName
		Subject    ResourceName

		// Checksum provides the checksum of the CSR on the server.
		Checksum []byte
	}

	CSRChange struct {
		CSR       CSR
		FieldList []string
	}

	ResultCSR struct {
		Result Result
		CSRs   []CSR
	}
)

func (c *Client) CreateCSR(pk CSR) error {
	return c.exec("CreateCSR", pk)
}
func (c *Client) SetCSR(pk CSR, fieldList []string) error {
	changeset := CSRChange{pk, fieldList}
	return c.exec("SetCSR", changeset)
}
func (c *Client) DeleteCSR(id string) error {
	pk := ResourceName{ID: id, Type: RTCSR}
	return c.exec("DeleteCSR", pk)
}
func (c *Client) ListCSR() ([]CSR, error) {
	result := &ResultCSR{}
	if err := c.query("ListCSR", Filter{}, result); err != nil {
		return []CSR{}, err
	}
	if result.Result.HasError {
		return []CSR{}, result.Result.Error
	}
	return result.CSRs, nil
}
func (c *Client) ShowCSR(id string) (CSR, error) {
	csr := ResourceName{ID: id, Type: RTCSR}
	result := &ResultCSR{}
	if err := c.query("ShowCSR", csr, result); err != nil {
		return CSR{}, err
	}
	if result.Result.HasError {
		return CSR{}, result.Result.Error
	}
	for _, csr := range result.CSRs {
		return csr, nil
	}
	return CSR{}, nil
}

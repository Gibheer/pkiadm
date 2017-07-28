package pkiadm

import (
	"time"
)

type (
	Certificate struct {
		ID string

		IsCA     bool
		Duration time.Duration
		Created  time.Time

		PrivateKey ResourceName
		Serial     ResourceName
		CSR        ResourceName
		CA         ResourceName

		// Checksum is filled by the server with the checksum of the currently valid
		// certificate.
		Checksum []byte
	}

	CertificateChange struct {
		Certificate Certificate
		FieldList   []string
	}

	ResultCertificate struct {
		Result       Result
		Certificates []Certificate
	}
)

// CreatePrivateKey sends a RPC request to create a new private key.
func (c *Client) CreateCertificate(pk Certificate) error {
	return c.exec("CreateCertificate", pk)
}
func (c *Client) SetCertificate(pk Certificate, fieldList []string) error {
	changeset := CertificateChange{pk, fieldList}
	return c.exec("SetCertificate", changeset)
}
func (c *Client) DeleteCertificate(id string) error {
	pk := ResourceName{ID: id, Type: RTCertificate}
	return c.exec("DeleteCertificate", pk)
}
func (c *Client) ListCertificate() ([]Certificate, error) {
	result := &ResultCertificate{}
	if err := c.query("ListCertificate", Filter{}, result); err != nil {
		return []Certificate{}, err
	}
	if result.Result.HasError {
		return []Certificate{}, result.Result.Error
	}
	return result.Certificates, nil
}
func (c *Client) ShowCertificate(id string) (Certificate, error) {
	pk := ResourceName{ID: id, Type: RTCertificate}
	result := &ResultCertificate{}
	if err := c.query("ShowCertificate", pk, result); err != nil {
		return Certificate{}, err
	}
	if result.Result.HasError {
		return Certificate{}, result.Result.Error
	}
	for _, privateKey := range result.Certificates {
		return privateKey, nil
	}
	return Certificate{}, nil
}

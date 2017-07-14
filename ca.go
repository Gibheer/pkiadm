package pkiadm

import (
	"strings"
)

const (
	CALocal CAType = iota
	CALetsEncrypt
	CAUnknown
)

type (
	CAType uint

	CA struct {
		ID          string
		Type        CAType
		Certificate ResourceName
	}
	ResultCA struct {
		Result Result
		CAs    []CA
	}
	CAChange struct {
		CA        CA
		FieldList []string
	}
)

// CreateCA sends a RPC request to create a new private key.
func (c *Client) CreateCA(pk CA) error {
	return c.exec("CreateCA", pk)
}
func (c *Client) SetCA(pk CA, fieldList []string) error {
	changeset := CAChange{pk, fieldList}
	return c.exec("SetCA", changeset)
}
func (c *Client) DeleteCA(id string) error {
	pk := ResourceName{ID: id, Type: RTCA}
	return c.exec("DeleteCA", pk)
}
func (c *Client) ListCA() ([]CA, error) {
	result := &ResultCA{}
	if err := c.query("ListCA", Filter{}, result); err != nil {
		return []CA{}, err
	}
	if result.Result.HasError {
		return []CA{}, result.Result.Error
	}
	return result.CAs, nil
}
func (c *Client) ShowCA(id string) (CA, error) {
	ca := ResourceName{ID: id, Type: RTCA}
	result := &ResultCA{}
	if err := c.query("ShowCA", ca, result); err != nil {
		return CA{}, err
	}
	if result.Result.HasError {
		return CA{}, result.Result.Error
	}
	for _, privateKey := range result.CAs {
		return privateKey, nil
	}
	return CA{}, nil
}

func (ct CAType) String() string {
	switch ct {
	case CALocal:
		return "local"
	case CALetsEncrypt:
		return "LetsEncrypt"
	default:
		return "unknown"
	}
}

func StringToCAType(in string) CAType {
	switch strings.ToLower(in) {
	case "local":
		return CALocal
	case "letsencrypt":
		return CALetsEncrypt
	default:
		return CAUnknown
	}
}

package pkiadm

const (
	PKTRSA PrivateKeyType = iota
	PKTECDSA
	PKTED25519
	PKTUnknown
)

type (
	PrivateKey struct {
		ID       string
		Type     PrivateKeyType
		Bits     uint
		Checksum []byte // This field is only set by the server
	}
	PrivateKeyChange struct {
		PrivateKey PrivateKey
		FieldList  []string
	}
	ResultPrivateKey struct {
		Result      Result
		PrivateKeys []PrivateKey
	}
	PrivateKeyType uint
)

// CreatePrivateKey sends a RPC request to create a new private key.
func (c *Client) CreatePrivateKey(pk PrivateKey) error {
	return c.exec("CreatePrivateKey", pk)
}
func (c *Client) SetPrivateKey(pk PrivateKey, fieldList []string) error {
	changeset := PrivateKeyChange{pk, fieldList}
	return c.exec("SetPrivateKey", changeset)
}
func (c *Client) DeletePrivateKey(id string) error {
	pk := ResourceName{ID: id, Type: RTPrivateKey}
	return c.exec("DeletePrivateKey", pk)
}
func (c *Client) ListPrivateKey() ([]PrivateKey, error) {
	result := &ResultPrivateKey{}
	if err := c.query("ListPrivateKey", Filter{}, result); err != nil {
		return []PrivateKey{}, err
	}
	if result.Result.HasError {
		return []PrivateKey{}, result.Result.Error
	}
	return result.PrivateKeys, nil
}
func (c *Client) ShowPrivateKey(id string) (PrivateKey, error) {
	pk := ResourceName{ID: id, Type: RTPrivateKey}
	result := &ResultPrivateKey{}
	if err := c.query("ShowPrivateKey", pk, result); err != nil {
		return PrivateKey{}, err
	}
	if result.Result.HasError {
		return PrivateKey{}, result.Result.Error
	}
	for _, privateKey := range result.PrivateKeys {
		return privateKey, nil
	}
	return PrivateKey{}, nil
}

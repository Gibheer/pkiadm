package pkiadm

type (
	PublicKey struct {
		ID string

		PrivateKey ResourceName
		// The following attributes are filled in by the server and ignored
		// otherwise.
		Type     PrivateKeyType // mark the type of the public key
		Checksum []byte
	}

	PublicKeyChange struct {
		FieldList []string
		PublicKey PublicKey
	}

	ResultPublicKey struct {
		Result     Result
		PublicKeys []PublicKey
	}
)

func (c *Client) CreatePublicKey(pub PublicKey) error {
	return c.exec("CreatePublicKey", pub)
}

func (c *Client) SetPublicKey(pub PublicKey, fieldList []string) error {
	changeset := PublicKeyChange{fieldList, pub}
	return c.exec("SetPublicKey", changeset)
}

func (c *Client) DeletePublicKey(pub PublicKey) error {
	return c.exec("DeletePublicKey", pub)
}

func (c *Client) ListPublicKey() ([]PublicKey, error) {
	result := &ResultPublicKey{}
	if err := c.query("ListPublicKey", Filter{}, result); err != nil {
		return []PublicKey{}, err
	}
	if result.Result.HasError {
		return []PublicKey{}, result.Result.Error
	}
	return result.PublicKeys, nil
}

func (c *Client) ShowPublicKey(id string) (PublicKey, error) {
	pk := ResourceName{ID: id, Type: RTPublicKey}
	result := &ResultPublicKey{}
	if err := c.query("ShowPublicKey", pk, result); err != nil {
		return PublicKey{}, err
	}
	if result.Result.HasError {
		return PublicKey{}, result.Result.Error
	}
	for _, publicKey := range result.PublicKeys {
		return publicKey, nil
	}
	return PublicKey{}, nil
}

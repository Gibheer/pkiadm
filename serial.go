package pkiadm

type (
	Serial struct {
		ID  string
		Min int64
		Max int64
	}

	SerialChange struct {
		Serial    Serial
		FieldList []string
	}

	ResultSerial struct {
		Result  Result
		Serials []Serial
	}
)

// CreateSerial sends a RPC request to create a new private key.
func (c *Client) CreateSerial(ser Serial) error {
	return c.exec("CreateSerial", ser)
}
func (c *Client) SetSerial(ser Serial, fieldList []string) error {
	changeset := SerialChange{ser, fieldList}
	return c.exec("SetSerial", changeset)
}
func (c *Client) DeleteSerial(id string) error {
	ser := ResourceName{ID: id, Type: RTSerial}
	return c.exec("DeleteSerial", ser)
}
func (c *Client) ListSerial() ([]Serial, error) {
	result := &ResultSerial{}
	if err := c.query("ListSerial", Filter{}, result); err != nil {
		return []Serial{}, err
	}
	if result.Result.HasError {
		return []Serial{}, result.Result.Error
	}
	return result.Serials, nil
}
func (c *Client) ShowSerial(id string) (Serial, error) {
	ser := ResourceName{ID: id, Type: RTSerial}
	result := &ResultSerial{}
	if err := c.query("ShowSerial", ser, result); err != nil {
		return Serial{}, err
	}
	if result.Result.HasError {
		return Serial{}, result.Result.Error
	}
	for _, privateKey := range result.Serials {
		return privateKey, nil
	}
	return Serial{}, nil
}

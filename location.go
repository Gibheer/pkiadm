package pkiadm

type (
	Location struct {
		ID           string
		Path         string
		Dependencies []ResourceName
		PreCommand   string
		PostCommand  string
		Checksum     []byte
	}
	LocationChange struct {
		Location  Location
		FieldList []string
	}

	ResultLocations struct {
		Result    Result
		Locations []Location
	}
)

func (c *Client) CreateLocation(loc Location) error {
	return c.exec("CreateLocation", loc)
}

func (c *Client) DeleteLocation(id string) error {
	loc := ResourceName{ID: id, Type: RTLocation}
	return c.exec("DeleteLocation", loc)
}

func (c *Client) SetLocation(loc Location, fieldList []string) error {
	changeset := LocationChange{loc, fieldList}
	return c.exec("SetLocation", changeset)
}

func (c *Client) ShowLocation(id string) (Location, error) {
	loc := ResourceName{ID: id, Type: RTLocation}
	result := &ResultLocations{}
	if err := c.query("ShowLocation", loc, result); err != nil {
		return Location{}, err
	}
	if result.Result.HasError {
		return Location{}, result.Result.Error
	}
	for _, location := range result.Locations {
		return location, nil
	}
	return Location{}, nil
}

func (c *Client) ListLocation() ([]Location, error) {
	result := &ResultLocations{}
	if err := c.query("ListLocation", Filter{}, result); err != nil {
		return []Location{}, err
	}
	if result.Result.HasError {
		return []Location{}, result.Result.Error
	}
	return result.Locations, nil
}

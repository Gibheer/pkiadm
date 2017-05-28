package pkiadm

import (
	"crypto/x509/pkix"
)

type (
	Subject struct {
		ID   string
		Name pkix.Name
	}
	// SubjectChange is a struct containing the fields that were changed.
	SubjectChange struct {
		Subject   Subject
		FieldList []string // The list of fields that were changed.
	}

	ResultSubjects struct {
		Result   Result
		Subjects []Subject
	}
)

func (c *Client) CreateSubject(subj Subject) error {
	return c.exec("CreateSubject", subj)
}

func (c *Client) DeleteSubject(id string) error {
	subj := ResourceName{ID: id, Type: RTSubject}
	return c.exec("DeleteSubject", subj)
}

func (c *Client) SetSubject(subj Subject, fieldList []string) error {
	changeset := SubjectChange{subj, fieldList}
	return c.exec("SetSubject", changeset)
}

func (c *Client) ShowSubject(id string) (Subject, error) {
	subj := ResourceName{ID: id, Type: RTSubject}
	result := &ResultSubjects{}
	if err := c.query("ShowSubject", subj, result); err != nil {
		return Subject{}, err
	}
	if result.Result.HasError {
		return Subject{}, result.Result.Error
	}
	for _, subject := range result.Subjects {
		return subject, nil
	}
	return Subject{}, nil
}

func (c *Client) ListSubject() ([]Subject, error) {
	result := &ResultSubjects{}
	if err := c.query("ListSubjects", Filter{}, result); err != nil {
		return []Subject{}, err
	}
	if result.Result.HasError {
		return []Subject{}, result.Result.Error
	}
	return result.Subjects, nil
}

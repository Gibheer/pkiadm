package pkiadm

import (
	"fmt"
	"net/rpc"
)

const (
	// ProtoIdent is the name of the resource container provided by the server.
	ProtoIdent = "pkiadm"
)

type (
	Client struct {
		c *rpc.Client
	}
)

// Create a new Client instance using the provided configuration.
func NewClient(cfg Config) (*Client, error) {
	conn, err := rpc.Dial("unix", cfg.Path)
	if err != nil {
		return nil, err
	}
	return &Client{conn}, nil
}

// Close the client connection with the server. When the Connection is already
// closed, the returned error will be net.rpc.ErrShutdown.
func (c *Client) Close() error {
	return c.c.Close()
}

// Exec sends `cmd` to the server with the given input and evaluates the
// standard Result for error messages.
// When one is found, the error is returned.
func (c *Client) exec(cmd string, input interface{}) error {
	result := &Result{}
	if err := c.c.Call(fmt.Sprintf("%s.%s", ProtoIdent, cmd), input, result); err != nil {
		return err
	}
	if result.HasError {
		return result.Error
	}
	return nil
}

// query can be used to call a function returning a result set.
func (c *Client) query(cmd string, input interface{}, result interface{}) error {
	if err := c.c.Call(fmt.Sprintf("%s.%s", ProtoIdent, cmd), input, result); err != nil {
		return err
	}
	return nil
}

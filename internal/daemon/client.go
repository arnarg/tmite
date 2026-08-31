package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Client is an NDJSON connection to the daemon, shared by the code,
// list, and cancel commands. Send writes one request line; Recv reads
// the next line, which is either a Response or a streamed Event.
type Client struct {
	conn net.Conn
	sc   *bufio.Scanner

	mu  sync.Mutex
	enc *json.Encoder
}

// Dial connects to the daemon socket.
func Dial(ctx context.Context, socketPath string) (*Client, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("daemon: dialing %s: %w", socketPath, err)
	}
	c := &Client{conn: conn, enc: json.NewEncoder(conn)}
	c.sc = bufio.NewScanner(conn)
	c.sc.Buffer(make([]byte, 0, 4096), maxRequestSize)
	return c, nil
}

// Close closes the connection.
func (c *Client) Close() error { return c.conn.Close() }

// SetReadDeadline bounds the next Recv.
func (c *Client) SetReadDeadline(t time.Time) error { return c.conn.SetReadDeadline(t) }

// Send writes one request line.
func (c *Client) Send(req Request) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.enc.Encode(req)
}

// Recv reads the next line. Exactly one of the response and event
// results is non-nil, except on error. io.EOF means the daemon closed
// the connection.
func (c *Client) Recv() (resp *Response, ev *Event, err error) {
	if !c.sc.Scan() {
		if e := c.sc.Err(); e != nil {
			return nil, nil, e
		}
		return nil, nil, io.EOF
	}
	line := c.sc.Bytes()
	var probe struct {
		Event string `json:"event"`
	}
	if err := json.Unmarshal(line, &probe); err == nil && probe.Event != "" {
		var ev Event
		if err := json.Unmarshal(line, &ev); err != nil {
			return nil, nil, fmt.Errorf("daemon: bad event %s: %w", line, err)
		}
		return nil, &ev, nil
	}
	var r Response
	if err := json.Unmarshal(line, &r); err != nil {
		return nil, nil, fmt.Errorf("daemon: bad response %s: %w", line, err)
	}
	return &r, nil, nil
}

package gelf

import (
	"crypto/tls"
	"fmt"
	"os"
	"time"
)

type TLSWriter struct {
	TCPWriter
	TlsConfig *tls.Config
}

func NewTLSWriter(addr string, tlsConfig *tls.Config) (*TLSWriter, error) {
	w := new(TLSWriter)
	w.MaxReconnect = DefaultMaxReconnect
	w.ReconnectDelay = DefaultReconnectDelay
	w.proto = "tls"
	w.addr = addr
	w.TlsConfig = tlsConfig

	var err error
	if w.conn, err = tls.Dial("tcp", addr, w.TlsConfig); err != nil {
		return nil, err
	}
	if w.hostname, err = os.Hostname(); err != nil {
		return nil, err
	}

	return w, nil
}

// WriteMessage sends the specified message to the GELF server
// specified in the call to New().  It assumes all the fields are
// filled out appropriately.  In general, clients will want to use
// Write, rather than WriteMessage.
func (w *TLSWriter) WriteMessage(m *Message) (err error) {
	buf := newBuffer()
	defer bufPool.Put(buf)
	messageBytes, err := m.toBytes(buf)
	if err != nil {
		return err
	}

	messageBytes = append(messageBytes, 0)

	n, err := w.writeToSocketWithReconnectAttempts(messageBytes)
	if err != nil {
		return err
	}
	if n != len(messageBytes) {
		return fmt.Errorf("bad write (%d/%d)", n, len(messageBytes))
	}

	return nil
}

func (w *TLSWriter) Write(p []byte) (n int, err error) {
	file, line := getCallerIgnoringLogMulti(1)

	m := constructMessage(p, w.hostname, w.Facility, file, line)

	if err = w.WriteMessage(m); err != nil {
		return 0, err
	}

	return len(p), nil
}

func (w *TLSWriter) writeToSocketWithReconnectAttempts(zBytes []byte) (n int, err error) {
	var errConn error
	var i int

	w.mu.Lock()
	for i = 0; i <= w.MaxReconnect; i++ {
		errConn = nil

		if w.conn != nil {
			n, err = w.conn.Write(zBytes)
		} else {
			err = fmt.Errorf("connection was nil, will attempt to reconnect")
		}
		if err != nil {
			time.Sleep(w.ReconnectDelay * time.Second)
			w.conn, errConn = tls.Dial("tcp", w.addr, w.TlsConfig)
		} else {
			break
		}
	}
	w.mu.Unlock()

	if i > w.MaxReconnect {
		return 0, fmt.Errorf("maximum reconnection attempts were reached; giving up")
	}
	if errConn != nil {
		return 0, fmt.Errorf("write failed: %s\nreconnection failed: %s", err, errConn)
	}
	return n, nil
}

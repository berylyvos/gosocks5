package gosocks5

import (
	"io"
)

const (
	MethodNoAuth       Method = 0x00 // NO AUTHENTICATION REQUIRED
	MethodGSSAPI       Method = 0x01 // GSSAPI
	MethodPassword     Method = 0x02 // USERNAME/PASSWORD
	MethodNoAcceptable Method = 0xff // NO ACCEPTABLE METHODS
)

const (
	SubnegotiationVerPassword = 0x01
	PasswordAuthSuccess       = 0x00
	PasswordAuthFailure       = 0xff
)

type Method = byte

type ClientAuthMessage struct {
	Version byte
	NMethod byte
	Methods []Method
}

type ClientPasswordMessage struct {
	Username string
	Password string
}

// The client connects to the server, and sends a version
// identifier/method selection message:
//
//	+----+----------+----------+
//	|VER | NMETHODS | METHODS  |
//	+----+----------+----------+
//	| 1  |    1     | 1 to 255 |
//	+----+----------+----------+
//
// The VER field is set to X'05' for this version of the protocol.  The
// NMETHODS field contains the number of method identifier octets that
// appear in the METHODS field.
func NewClientAuthMessage(conn io.Reader) (*ClientAuthMessage, error) {
	buf := make([]byte, 2)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		return nil, err
	}

	if buf[0] != SOCKS5_VER {
		return nil, ErrVerNotSupport
	}

	nmethod := buf[1]
	buf = make([]byte, nmethod)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		return nil, err
	}

	return &ClientAuthMessage{
		Version: SOCKS5_VER,
		NMethod: nmethod,
		Methods: buf,
	}, nil
}

// The server selects from one of the methods given in METHODS, and
// sends a METHOD selection message:
//
//	+----+--------+
//	|VER | METHOD |
//	+----+--------+
//	| 1  |   1    |
//	+----+--------+
//
// If the selected METHOD is X'FF', none of the methods listed by the
// client are acceptable, and the client MUST close the connection.
func NewServerAuthMessage(conn io.Writer, method Method) error {
	buf := []byte{SOCKS5_VER, method}
	_, err := conn.Write(buf)
	return err
}

// Once the SOCKS V5 server has started, and the client has selected the
// Username/Password Authentication protocol, the Username/Password
// subnegotiation begins.  This begins with the client producing a
// Username/Password request:
//
//	+----+------+----------+------+----------+
//	|VER | ULEN |  UNAME   | PLEN |  PASSWD  |
//	+----+------+----------+------+----------+
//	| 1  |  1   | 1 to 255 |  1   | 1 to 255 |
//	+----+------+----------+------+----------+
//
// The VER field contains the current version of the subnegotiation,
// which is X'01'.
func NewClientPasswordMessage(conn io.Reader) (*ClientPasswordMessage, error) {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}

	ver, ulen := buf[0], buf[1]
	if ver != SubnegotiationVerPassword {
		return nil, ErrMethodVerNotSupport
	}

	buf = make([]byte, ulen+1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}

	uname, plen := buf[:ulen], buf[ulen]
	if plen > ulen {
		buf = make([]byte, plen)
	}

	if _, err := io.ReadFull(conn, buf[:plen]); err != nil {
		return nil, err
	}

	return &ClientPasswordMessage{
		Username: string(uname),
		Password: string(buf[:plen]),
	}, nil
}

// The server verifies the supplied UNAME and PASSWD, and sends the
// following response:
//
//	+----+--------+
//	|VER | STATUS |
//	+----+--------+
//	| 1  |   1    |
//	+----+--------+
//
// A STATUS field of X'00' indicates success. If the server returns a
// `failure' (STATUS value other than X'00') status, it MUST close the
// connection.
func WriteServerPasswordMessage(conn io.Writer, status byte) error {
	_, err := conn.Write([]byte{SubnegotiationVerPassword, status})
	return err
}

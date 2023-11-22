package gosocks5

import (
	"errors"
	"io"
)

const (
	MethodNoAuth       Method = 0x00
	MethodGSSAPI       Method = 0x01
	MethodPassword     Method = 0x02
	MethodNoAcceptable Method = 0xff
)

type Method = byte

type ClientAuthMessage struct {
	Version byte
	NMethod byte
	Methods []Method
}

func NewClientAuthMessage(conn io.Reader) (*ClientAuthMessage, error) {
	// 1-version, 1-nMethod
	buf := make([]byte, 2)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		return nil, err
	}

	if buf[0] != SOCKS5_VER {
		return nil, errors.New("protocol version not support")
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

func NewServerAuthMessage(conn io.Writer, method Method) error {
	buf := []byte{SOCKS5_VER, method}
	_, err := conn.Write(buf)
	return err
}

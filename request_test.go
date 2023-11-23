package gosocks5

import (
	"bytes"
	"net"
	"reflect"
	"testing"
)

func TestNewClientRequestMessage(t *testing.T) {
	tests := []struct {
		Cmd      Command
		AddrType AType
		Addr     []byte
		Port     []byte
		Error    error
		Message  ClientRequestMessage
	}{
		{
			Cmd:      CmdConnect,
			AddrType: ATypIPv4,
			Addr:     []byte{123, 35, 13, 89},
			Port:     []byte{0x00, 0x50},
			Error:    nil,
			Message: ClientRequestMessage{
				Cmd:      CmdConnect,
				AddrType: ATypIPv4,
				Addr:     "123.35.13.89",
				Port:     80,
			},
		},
		{
			Cmd:      0x0a,
			AddrType: ATypIPv4,
			Addr:     []byte{123, 35, 13, 89},
			Port:     []byte{0x00, 0x50},
			Error:    ErrCmdNotSupport,
			Message: ClientRequestMessage{
				Cmd:      CmdConnect,
				AddrType: ATypIPv4,
				Addr:     "123.35.13.89",
				Port:     80,
			},
		},
	}

	for _, test := range tests {
		var buf bytes.Buffer
		buf.Write([]byte{SOCKS5_VER, test.Cmd, RSV, test.AddrType})
		buf.Write(test.Addr)
		buf.Write(test.Port)

		message, err := NewClientRequestMessage(&buf)
		if err != test.Error {
			t.Fatalf("expect %v, got %v\n", test.Error, err)
		}
		if err != nil {
			continue
		}

		if *message != test.Message {
			t.Fatalf("expect %+v, got %+v\n", test.Message, message)
		}
	}
}

func TestWriteRequestSuccessMessage(t *testing.T) {
	var buf bytes.Buffer
	bndAddr := net.IP([]byte{123, 123, 11, 22})
	bndPort := uint16(0x0439)
	err := WriteRequestSuccessMessage(&buf, bndAddr, bndPort)
	if err != nil {
		t.Fatal(err)
	}

	expect := []byte{SOCKS5_VER, RepSuccess, RSV, ATypIPv4, 123, 123, 11, 22, 0x04, 0x39}
	got := buf.Bytes()
	if !reflect.DeepEqual(expect, got) {
		t.Fatalf("message not match: expect %v, got %v", expect, got)
	}
}

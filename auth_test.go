package gosocks5

import (
	"bytes"
	"reflect"
	"testing"
)

func TestNewClientAuthMessage(t *testing.T) {
	t.Run("should generate a message", func(t *testing.T) {
		b := []byte{SOCKS5_VER, 2, MethodNoAuth, MethodGSSAPI}
		r := bytes.NewReader(b)

		message, err := NewClientAuthMessage(r)
		if err != nil {
			t.Fatalf("expect err == nil but got %v", err)
		}

		if message.Version != SOCKS5_VER {
			t.Fatalf("expect %v but got %v", SOCKS5_VER, message.Version)
		}
		if message.NMethod != 2 {
			t.Fatalf("expect %v but got %v", 2, message.NMethod)
		}
		if !reflect.DeepEqual(message.Methods, []byte{MethodNoAuth, MethodGSSAPI}) {
			t.Fatalf("expect %v but got %v", []byte{MethodNoAuth, MethodGSSAPI}, message.Methods)
		}
	})

	t.Run("methods length is shorter than nmethod", func(t *testing.T) {
		b := []byte{SOCKS5_VER, 2, MethodNoAuth}
		r := bytes.NewReader(b)

		_, err := NewClientAuthMessage(r)
		if err == nil {
			t.Fatalf("expect error != nil but got nil")
		}
	})
}

func TestNewServerAuthMessage(t *testing.T) {
	t.Run("should send noauth", func(t *testing.T) {
		var buf bytes.Buffer
		err := NewServerAuthMessage(&buf, MethodNoAuth)
		if err != nil {
			t.Fatalf("expect nil error but got %s", err)
		}

		got := buf.Bytes()
		if !reflect.DeepEqual(got, []byte{SOCKS5_VER, MethodNoAuth}) {
			t.Fatalf("expect send %v, but send %v", []byte{SOCKS5_VER, MethodNoAuth}, got)
		}
	})

	t.Run("should send no acceptable", func(t *testing.T) {
		var buf bytes.Buffer
		err := NewServerAuthMessage(&buf, MethodNoAcceptable)
		if err != nil {
			t.Fatalf("expect nil error but got %s", err)
		}

		got := buf.Bytes()
		if !reflect.DeepEqual(got, []byte{SOCKS5_VER, MethodNoAcceptable}) {
			t.Fatalf("expect send %v, but send %v", []byte{SOCKS5_VER, MethodNoAcceptable}, got)
		}
	})
}

func TestNewClientPasswordMessage(t *testing.T) {
	t.Run("valid password auth message", func(t *testing.T) {
		username, password := "admin", "123456"
		var buf bytes.Buffer
		buf.Write([]byte{SubnegotiationVerPassword, 5})
		buf.WriteString(username)
		buf.WriteByte(6)
		buf.WriteString(password)

		message, err := NewClientPasswordMessage(&buf)
		if err != nil {
			t.Fatalf("expect error == nil, got %s", err)
		}

		want := ClientPasswordMessage{Password: password, Username: username}
		if *message != want {
			t.Fatalf("expect message %#v, got %#v", *message, want)
		}
	})
}

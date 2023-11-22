package gosocks5

import (
	"bytes"
	"reflect"
	"testing"
)

func TestAuth(t *testing.T) {
	t.Run("a valid client auth message", func(t *testing.T) {
		var buf bytes.Buffer
		buf.Write([]byte{SOCKS5_VER, 2, MethodNoAuth, MethodGSSAPI})
		if err := auth(&buf); err != nil {
			t.Fatalf("expect error == nil but got %s", err)
		}

		want := []byte{SOCKS5_VER, MethodNoAuth}
		got := buf.Bytes()
		if !reflect.DeepEqual(want, got) {
			t.Fatalf("expect message %v but got %v", want, got)
		}
	})

	t.Run("an invalid client auth message", func(t *testing.T) {
		var buf bytes.Buffer
		buf.Write([]byte{SOCKS5_VER, 2, MethodNoAuth})
		if err := auth(&buf); err == nil {
			t.Fatalf("expect error == EOF but got nil")
		} else {
			t.Logf("%v", err)
		}
	})
}

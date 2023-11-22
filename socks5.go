package gosocks5

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
)

const SOCKS5_VER byte = 0x05

type Server interface {
	Run() error
}

type S5Server struct {
	IP   string
	Port int
}

func (s *S5Server) Run() error {
	addr := fmt.Sprintf("%s:%d", s.IP, s.Port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("connection failed from %s: %s", conn.RemoteAddr(), err)
			continue
		}

		go func() {
			defer conn.Close()
			if err = handleConnection(conn); err != nil {
				log.Printf("handle connection failed from %s: %s", conn.RemoteAddr(), err)
			}
		}()
	}
}

func handleConnection(conn net.Conn) error {
	if err := auth(conn); err != nil {
		return err
	}

	if _, err := request(conn); err != nil {
		return err
	}

	return nil
}

// The client enters a negotiation for the authentication method to be used,
// authenticates with the chosen method, then sends a relay request.
//
// The SOCKS server evaluates the request, and either establishes the
// appropriate connection or denies	it.
func auth(conn io.ReadWriter) error {
	clientMessage, err := NewClientAuthMessage(conn)
	if err != nil {
		return err
	}

	// only support no-auth
	var acceptable bool
	for _, method := range clientMessage.Methods {
		if method == MethodNoAuth {
			acceptable = true
			break
		}
	}

	if !acceptable {
		NewServerAuthMessage(conn, MethodNoAcceptable)
		return errors.New("method not acceptable, expect no-auth")
	}
	return NewServerAuthMessage(conn, MethodNoAuth)
}

// Once the method-dependent subnegotiation has completed, the client
// sends the request details.
//
// The SOCKS server will typically evaluate the request based on source
// and destination addresses, and return one or more reply messages, as
// appropriate for the request type.
func request(conn io.ReadWriter) (io.ReadWriteCloser, error) {

	return nil, nil
}

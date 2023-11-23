package gosocks5

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
)

const (
	SOCKS5_VER byte = 0x05
	RSV        byte = 0x00
)

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

	signalStream := make(chan os.Signal, 1)
	signal.Notify(signalStream, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-signalStream
		log.Println("SOCKS5 Server shutdown...")
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			return nil
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

	dstConn, err := request(conn)
	if err != nil {
		return err
	}

	return forward(conn, dstConn)
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
	message, err := NewClientRequestMessage(conn)
	log.Printf("%+v", message)
	if err != nil {
		return nil, err
	}

	if message.Cmd != CmdConnect {
		return nil, WriteRequestFailureMessage(conn, RepCommandNotSupported)
	}

	if message.AddrType == ATypIPv6 {
		return nil, WriteRequestFailureMessage(conn, RepAddressTypeNotSupported)
	}

	dstAddr := fmt.Sprintf("%s:%d", message.Addr, message.Port)
	dstConn, err := net.Dial("tcp", dstAddr)
	if err != nil {
		return nil, WriteRequestFailureMessage(conn, RepConnectionRefused)
	}

	bndAddr := dstConn.LocalAddr().(*net.TCPAddr)
	return dstConn, WriteRequestSuccessMessage(conn, bndAddr.IP, uint16(bndAddr.Port))
}

func forward(conn io.ReadWriter, dstConn io.ReadWriteCloser) error {
	defer dstConn.Close()

	// client -> dst
	go io.Copy(dstConn, conn)

	// client <- dst
	_, err := io.Copy(conn, dstConn)

	return err
}

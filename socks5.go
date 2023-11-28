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
	"time"
)

const (
	SOCKS5_VER byte = 0x05
	RSV        byte = 0x00
)

type Server interface {
	Run() error
}

type S5Server struct {
	IP     string
	Port   int
	Config *Config
}

type (
	PasswordChecker func(uname, pwd string) bool

	Config struct {
		AuthMethod Method
		PwdChecker PasswordChecker
		TCPTimeout time.Duration
	}
)

var (
	DefaultConfig = &Config{
		AuthMethod: MethodNoAuth,
		TCPTimeout: time.Second * 5,
	}
)

func (s *S5Server) initConfig() error {
	if s.Config == nil {
		s.Config = DefaultConfig
	}
	if s.Config.AuthMethod == MethodPassword && s.Config.PwdChecker == nil {
		return ErrPasswordCheckerNotSet
	}
	return nil
}

func (s *S5Server) Run() error {
	if err := s.initConfig(); err != nil {
		return err
	}

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
			if err = s.handleConnection(conn); err != nil {
				log.Printf("handle connection failed from %s: %s", conn.RemoteAddr(), err)
			}
		}()
	}
}

func (s *S5Server) handleConnection(conn net.Conn) error {
	if err := s.auth(conn); err != nil {
		return err
	}

	return s.request(conn)
}

// The client enters a negotiation for the authentication method to be used,
// authenticates with the chosen method, then sends a relay request.
//
// The SOCKS server evaluates the request, and either establishes the
// appropriate connection or denies	it.
//
// The client and server then enter a method-specific sub-negotiation.
func (s *S5Server) auth(conn io.ReadWriter) error {
	clientMessage, err := NewClientAuthMessage(conn)
	if err != nil {
		return err
	}
	log.Printf("client auth message: %+v", *clientMessage)

	// now we support no-auth, username/password
	var acceptable bool
	for _, method := range clientMessage.Methods {
		if method == s.Config.AuthMethod {
			acceptable = true
			break
		}
	}

	if !acceptable {
		NewServerAuthMessage(conn, MethodNoAcceptable)
		return errors.New("authentication method not acceptable")
	}
	if err := NewServerAuthMessage(conn, s.Config.AuthMethod); err != nil {
		return err
	}

	if s.Config.AuthMethod == MethodPassword {
		passwordMessage, err := NewClientPasswordMessage(conn)
		if err != nil {
			return err
		}

		if !s.Config.PwdChecker(passwordMessage.Username,
			passwordMessage.Password) {
			WriteServerPasswordMessage(conn, PasswordAuthFailure)
			return ErrPasswordAuthFailure
		}

		err = WriteServerPasswordMessage(conn, PasswordAuthSuccess)
		if err != nil {
			return err
		}
	}

	return nil
}

// Once the method-dependent subnegotiation has completed, the client
// sends the request details.
//
// The SOCKS server will typically evaluate the request based on source
// and destination addresses, and return one or more reply messages, as
// appropriate for the request type.
func (s *S5Server) request(conn io.ReadWriter) error {
	message, err := NewClientRequestMessage(conn)
	if err != nil {
		return err
	}
	log.Printf("client request: %+v", *message)

	if message.AddrType == ATypIPv6 {
		WriteRequestFailureMessage(conn, RepAddressTypeNotSupported)
		return ErrAtypNotSupport
	}

	if message.Cmd == CmdConnect {
		return s.handleTCPRequest(conn, message)
	} else if message.Cmd == CmdUDP {
		return s.handleUDPRequest()
	} else {
		WriteRequestFailureMessage(conn, RepCommandNotSupported)
		return ErrCmdNotSupport
	}
}

func (s *S5Server) handleTCPRequest(conn io.ReadWriter, message *ClientRequestMessage) error {
	dstAddr := fmt.Sprintf("%s:%d", message.Addr, message.Port)
	dstConn, err := net.DialTimeout("tcp", dstAddr, s.Config.TCPTimeout)
	if err != nil {
		WriteRequestFailureMessage(conn, RepConnectionRefused)
		return err
	}

	bndAddr := dstConn.LocalAddr().(*net.TCPAddr)
	if err := WriteRequestSuccessMessage(conn, bndAddr.IP, uint16(bndAddr.Port)); err != nil {
		return err
	}

	return forward(conn, dstConn)
}

func (s *S5Server) handleUDPRequest() error {
	return nil
}

func forward(conn io.ReadWriter, dstConn io.ReadWriteCloser) error {
	defer func() {
		if dstConn != nil {
			dstConn.Close()
		}
	}()

	// client -> dst
	go func() {
		io.Copy(dstConn, conn)
	}()

	// client <- dst
	if dstConn != nil {
		_, err := io.Copy(conn, dstConn)
		return err
	}

	return nil
}

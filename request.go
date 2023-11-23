package gosocks5

import (
	"io"
	"net"
)

// The SOCKS request is formed as follows:
//
//         +----+-----+-------+------+----------+----------+
//         |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
//         +----+-----+-------+------+----------+----------+
//         | 1  |  1  | X'00' |  1   | Variable |    2     |
//         +----+-----+-------+------+----------+----------+
//
// 		*  VER    protocol version: X'05'
// 		*  CMD
//			*  CONNECT X'01'
//			*  BIND X'02'
//			*  UDP ASSOCIATE X'03'
//
// 		*  RSV    RESERVED
// 		*  ATYP   address type of following address
//			*  IP V4 address: X'01'
//			*  DOMAINNAME: X'03'
//			*  IP V6 address: X'04'
//
// 		*  DST.ADDR       desired destination address
// 		*  DST.PORT desired destination port in network octet order
//

type ClientRequestMessage struct {
	Cmd      Command
	AddrType AType
	Addr     string
	Port     uint16
}

type (
	Command = byte
	AType   = byte
	RepType = byte
)

const (
	CmdConnect Command = 0x01
	CmdBind    Command = 0x02
	CmdUDP     Command = 0x03

	ATypIPv4   AType = 0x01
	ATypDomain AType = 0x03
	ATypIPv6   AType = 0x04

	LenPort = 2
	LenIPv4 = 4
	LenIPv6 = 16

	LenReplyHeader = 4
)

func NewClientRequestMessage(conn io.Reader) (*ClientRequestMessage, error) {
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}

	// check fields
	ver, cmd, rsv, atyp := buf[0], buf[1], buf[2], buf[3]
	if ver != SOCKS5_VER {
		return nil, ErrVerNotSupport
	}
	if cmd > CmdUDP {
		return nil, ErrCmdNotSupport
	}
	if rsv != RSV {
		return nil, ErrInvalidField
	}
	if atyp != ATypIPv4 && atyp != ATypDomain && atyp != ATypIPv6 {
		return nil, ErrAtypNotSupport
	}

	message := ClientRequestMessage{
		Cmd:      cmd,
		AddrType: atyp,
	}

	// DST.ADDR
	switch atyp {
	case ATypIPv6:
		buf = make([]byte, LenIPv6)
		fallthrough
	case ATypIPv4:
		if _, err := io.ReadFull(conn, buf); err != nil {
			return nil, err
		}
		ip := net.IP(buf)
		message.Addr = ip.String()
	case ATypDomain:
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return nil, err
		}
		domainLen := buf[0]
		if domainLen > LenIPv4 {
			buf = make([]byte, domainLen)
		}
		if _, err := io.ReadFull(conn, buf[:domainLen]); err != nil {
			return nil, err
		}
		message.Addr = string(buf[:domainLen])
	}

	// DST.PORT
	if _, err := io.ReadFull(conn, buf[:LenPort]); err != nil {
		return nil, err
	}
	message.Port = (uint16(buf[0]) << 8) + uint16(buf[1])

	return &message, nil
}

// The SOCKS request information is sent by the client as soon as it has
//    established a connection to the SOCKS server, and completed the
//    authentication negotiations.  The server evaluates the request, and
//    returns a reply formed as follows:

//         +----+-----+-------+------+----------+----------+
//         |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
//         +----+-----+-------+------+----------+----------+
//         | 1  |  1  | X'00' |  1   | Variable |    2     |
//         +----+-----+-------+------+----------+----------+
//
//		o  VER    protocol version: X'05'
//		o  REP    Reply field:
//			o  X'00' succeeded
//			o  X'01' general SOCKS server failure
//			o  X'02' connection not allowed by ruleset
//			o  X'03' Network unreachable
//			o  X'04' Host unreachable
//			o  X'05' Connection refused
//			o  X'06' TTL expired
//			o  X'07' Command not supported
//			o  X'08' Address type not supported
//			o  X'09' to X'FF' unassigned
//		o  RSV    RESERVED
//		o  ATYP   address type of following address
//			o  IP V4 address: X'01'
//			o  DOMAINNAME: X'03'
//			o  IP V6 address: X'04'
//		o  BND.ADDR       server bound address
//		o  BND.PORT       server bound port in network octet order
//

const (
	RepSuccess RepType = iota
	RepServerFailure
	RepConnectionNotAllowed
	RepNetworkUnreachable
	RepHostUnreachable
	RepConnectionRefused
	RepTTLExpired
	RepCommandNotSupported
	RepAddressTypeNotSupported
)

func WriteRequestSuccessMessage(conn io.Writer, bndAddr net.IP, bndPort uint16) error {
	addrType := ATypIPv4
	if len(bndAddr) == LenIPv6 {
		addrType = ATypIPv6
	}

	buf := make([]byte, 0, LenReplyHeader+len(bndAddr)+LenPort)
	buf = append(buf, SOCKS5_VER, RepSuccess, RSV, addrType)
	buf = append(buf, bndAddr...)
	buf = append(buf, byte(bndPort>>8), byte(bndPort&0xff))

	_, err := conn.Write(buf)
	return err
}

func WriteRequestFailureMessage(conn io.Writer, replyType RepType) error {
	_, err := conn.Write([]byte{SOCKS5_VER, replyType, RSV, ATypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

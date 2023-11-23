package gosocks5

import "errors"

var (
	ErrInvalidField   = errors.New("invalid field")
	ErrVerNotSupport  = errors.New("protocol version not support")
	ErrCmdNotSupport  = errors.New("request command not support")
	ErrAtypNotSupport = errors.New("address type not support")
)

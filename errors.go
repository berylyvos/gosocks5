package gosocks5

import "errors"

var (
	ErrInvalidField          = errors.New("invalid field")
	ErrVerNotSupport         = errors.New("protocol version not support")
	ErrCmdNotSupport         = errors.New("request command not support")
	ErrAtypNotSupport        = errors.New("address type not support")
	ErrMethodVerNotSupport   = errors.New("sub-negotiation method version not supported")
	ErrPasswordAuthFailure   = errors.New("error authenticating username/password")
	ErrPasswordCheckerNotSet = errors.New("error password checker not set")
)

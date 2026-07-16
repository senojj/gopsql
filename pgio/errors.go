package pgio

import "errors"

var (
	ErrValueUnderflow     = errors.New("partial value")
	ErrValueOverflow      = errors.New("value too large")
	ErrUnknownMessageType = errors.New("unknown message type")
	ErrUnknownAuthType    = errors.New("unknown authentication type")
	ErrUnknownCode        = errors.New("unknown code")
)

package pgwire

import (
	"gopsql/pgio"
	"math"
)

var _ Message = &AuthenticationGSSContinue{}
var _ Backend = &AuthenticationGSSContinue{}

type AuthenticationGSSContinue struct {
	Data []byte
}

func (x *AuthenticationGSSContinue) message() {}

func (x *AuthenticationGSSContinue) backend() {}

func (x *AuthenticationGSSContinue) AppendBinary(b []byte) ([]byte, error) {
	sizeData := len(x.Data)
	length := sizeMessageLength + sizeAuthKind + sizeData

	if length > math.MaxInt32 {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(byte(MsgAuthentication))
	buf.AppendInt32(int32(length))
	buf.AppendInt32(int32(AuthGSSContinue))
	buf.AppendByte(x.Data...)
	return buf.Bytes(), nil
}

func (x *AuthenticationGSSContinue) UnmarshalBinary(b []byte) error {
	kind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if kind != byte(MsgAuthentication) {
		return unexpectedKind(kind, byte(MsgAuthentication))
	}

	authKind, b, err := pgio.ShiftInt32(b)
	if err != nil {
		return invalidFormat(err)
	}

	if authKind != int32(AuthGSSContinue) {
		return unexpectedAuthKind(authKind, int32(AuthGSSContinue))
	}
	x.Data = make([]byte, len(b))
	copy(x.Data, b)
	return nil
}

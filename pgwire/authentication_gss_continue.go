package pgwire

import (
	"gopsql/pgio"
	"math"
)

const KindAuthGSSContinue int32 = 8

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
	buf.AppendByte(KindAuthentication)
	buf.AppendInt32(int32(length))
	buf.AppendInt32(KindAuthGSSContinue)
	buf.AppendByte(x.Data...)
	return buf.Bytes(), nil
}

func (x *AuthenticationGSSContinue) UnmarshalBinary(b []byte) error {
	pgwireKind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if pgwireKind != KindAuthentication {
		return unexpectedKind(pgwireKind, KindAuthentication)
	}

	authKind, b, err := pgio.ShiftInt32(b)
	if err != nil {
		return invalidFormat(err)
	}

	if authKind != KindAuthGSSContinue {
		return unexpectedAuthKind(authKind, KindAuthGSSContinue)
	}
	x.Data = make([]byte, len(b))
	copy(x.Data, b)
	return nil
}

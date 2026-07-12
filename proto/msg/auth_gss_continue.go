package msg

import (
	"gopsql/internal/bytex"
	"math"
)

const KindAuthGSSContinue int32 = 8

var _ Message = &AuthGSSContinue{}
var _ Backend = &AuthGSSContinue{}

type AuthGSSContinue struct {
	Data []byte
}

func (x *AuthGSSContinue) message() {}

func (x *AuthGSSContinue) backend() {}

func (x *AuthGSSContinue) AppendBinary(b []byte) ([]byte, error) {
	sizeData := len(x.Data)
	length := sizeMessageLength + sizeAuthKind + sizeData

	if length > math.MaxInt32 {
		return b, invalidFormat(bytex.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	buf := bytex.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(KindAuthentication)
	buf.AppendInt32(int32(length))
	buf.AppendInt32(KindAuthGSSContinue)
	buf.AppendByte(x.Data...)
	return buf.Bytes(), nil
}

func (x *AuthGSSContinue) UnmarshalBinary(b []byte) error {
	msgKind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if msgKind != KindAuthentication {
		return unexpectedKind(msgKind, KindAuthentication)
	}

	authKind, b, err := bytex.ShiftInt32(b)
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

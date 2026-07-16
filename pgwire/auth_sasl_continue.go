package pgwire

import (
	"gopsql/pgio"
	"math"
)

const KindAuthSASLContinue int32 = 11

var _ Message = &AuthSASLContinue{}
var _ Backend = &AuthSASLContinue{}

type AuthSASLContinue struct {
	Data []byte
}

func (x *AuthSASLContinue) message() {}

func (x *AuthSASLContinue) backend() {}

func (x *AuthSASLContinue) AppendBinary(b []byte) ([]byte, error) {
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
	buf.AppendInt32(KindAuthSASLContinue)
	buf.AppendByte(x.Data...)
	return buf.Bytes(), nil
}

func (x *AuthSASLContinue) UnmarshalBinary(b []byte) error {
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

	if authKind != KindAuthSASLContinue {
		return unexpectedAuthKind(authKind, KindAuthSASLContinue)
	}
	x.Data = make([]byte, len(b))
	copy(x.Data, b)
	return nil
}

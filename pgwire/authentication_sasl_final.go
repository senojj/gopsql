package pgwire

import (
	"gopsql/pgio"
	"math"
)

const KindAuthSASLFinal int32 = 12

var _ Message = &AuthenticationSASLFinal{}
var _ Backend = &AuthenticationSASLFinal{}

type AuthenticationSASLFinal struct {
	Data []byte
}

func (x *AuthenticationSASLFinal) message() {}

func (x *AuthenticationSASLFinal) backend() {}

func (x *AuthenticationSASLFinal) AppendBinary(b []byte) ([]byte, error) {
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
	buf.AppendInt32(KindAuthSASLFinal)
	buf.AppendByte(x.Data...)
	return buf.Bytes(), nil
}

func (x *AuthenticationSASLFinal) UnmarshalBinary(b []byte) error {
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

	if authKind != KindAuthSASLFinal {
		return unexpectedAuthKind(authKind, KindAuthSASLFinal)
	}
	x.Data = make([]byte, len(b))
	copy(x.Data, b)
	return nil
}

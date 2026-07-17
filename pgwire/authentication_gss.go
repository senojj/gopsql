package pgwire

import (
	"gopsql/pgio"
)

const KindAuthGSS int32 = 7

var _ Message = &AuthenticationGSS{}
var _ Backend = &AuthenticationGSS{}

type AuthenticationGSS struct{}

func (x *AuthenticationGSS) message() {}

func (x *AuthenticationGSS) backend() {}

func (x *AuthenticationGSS) AppendBinary(b []byte) ([]byte, error) {
	const length = sizeMessageLength + sizeAuthKind
	const size = sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(KindAuthentication)
	buf.AppendInt32(int32(length))
	buf.AppendInt32(KindAuthGSS)
	return buf.Bytes(), nil
}

func (x *AuthenticationGSS) UnmarshalBinary(b []byte) error {
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

	if authKind != KindAuthGSS {
		return unexpectedAuthKind(authKind, KindAuthGSS)
	}
	if len(b) > 0 {
		return invalidFormat(pgio.ErrValueOverflow)
	}
	return nil
}

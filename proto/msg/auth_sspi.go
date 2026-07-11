package msg

import (
	"gopsql/internal/bytex"
)

const KindAuthSSPI int32 = 9

var _ Message = &AuthSSPI{}
var _ Backend = &AuthSSPI{}

type AuthSSPI struct{}

func (x *AuthSSPI) message() {}

func (x *AuthSSPI) backend() {}

func (x *AuthSSPI) AppendBinary(b []byte) ([]byte, error) {
	const length = sizeMessageLength + sizeAuthKind
	const size = sizeMessageKind + length

	buf := bytex.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(KindAuthentication)
	buf.AppendInt32(int32(length))
	buf.AppendInt32(KindAuthSSPI)
	return buf.Bytes(), nil
}

func (x *AuthSSPI) UnmarshalBinary(b []byte) error {
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

	if authKind != KindAuthSSPI {
		return unexpectedAuthKind(authKind, KindAuthSSPI)
	}

	if len(b) > 0 {
		return invalidFormat(bytex.ErrValueOverflow)
	}
	return nil
}

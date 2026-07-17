package pgwire

import (
	"gopsql/pgio"
	"math"
)

var _ Message = &AuthenticationSASL{}
var _ Backend = &AuthenticationSASL{}

type AuthenticationSASL struct {
	Mechanisms []string
}

func (x *AuthenticationSASL) message() {}

func (x *AuthenticationSASL) backend() {}

func (x *AuthenticationSASL) AppendBinary(b []byte) ([]byte, error) {
	countMechanisms := len(x.Mechanisms)
	sizeMechanisms := 0

	for i := range countMechanisms {
		sizeMechanisms += len(x.Mechanisms[i]) + 1 // null terminated string
	}
	sizeMechanisms += 1 // null terminated list

	length := sizeMessageLength + sizeAuthKind + sizeMechanisms

	if length > math.MaxInt32 {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(byte(MsgAuthentication))
	buf.AppendInt32(int32(length))
	buf.AppendInt32(int32(AuthSASL))
	buf.AppendString(x.Mechanisms...)
	buf.AppendByte(0x0)
	return buf.Bytes(), nil
}

func (x *AuthenticationSASL) UnmarshalBinary(b []byte) error {
	kind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if kind != byte(MsgAuthentication) {
		return unexpectedKind(kind, byte(MsgAuthentication))
	}

	buf := pgio.NewBuffer(b)

	authKind, err := buf.ShiftInt32()
	if err != nil {
		return invalidFormat(err)
	}

	if authKind != int32(AuthSASL) {
		return unexpectedAuthKind(authKind, int32(AuthSASL))
	}
	x.Mechanisms = make([]string, 0, buf.Count(NullByte))

	for {
		var mechanism string
		var err error

		mechanism, err = buf.ShiftString()
		if err != nil {
			return invalidFormat(err)
		}

		if len(mechanism) == 0 {
			break
		}
		x.Mechanisms = append(x.Mechanisms, mechanism)
	}
	return nil
}

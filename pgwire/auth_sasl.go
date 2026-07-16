package pgwire

import (
	"gopsql/pgio"
	"math"
)

const KindAuthSASL int32 = 10

var _ Message = &AuthSASL{}
var _ Backend = &AuthSASL{}

type AuthSASL struct {
	Mechanisms []string
}

func (x *AuthSASL) message() {}

func (x *AuthSASL) backend() {}

func (x *AuthSASL) AppendBinary(b []byte) ([]byte, error) {
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
	buf.AppendByte(KindAuthentication)
	buf.AppendInt32(int32(length))
	buf.AppendInt32(KindAuthSASL)
	buf.AppendString(x.Mechanisms...)
	buf.AppendByte(0x0)
	return buf.Bytes(), nil
}

func (x *AuthSASL) UnmarshalBinary(b []byte) error {
	pgwireKind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if pgwireKind != KindAuthentication {
		return unexpectedKind(pgwireKind, KindAuthentication)
	}

	buf := pgio.NewBuffer(b)

	authKind, err := buf.ShiftInt32()
	if err != nil {
		return invalidFormat(err)
	}

	if authKind != KindAuthSASL {
		return unexpectedAuthKind(authKind, KindAuthSASL)
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

package pgwire

import (
	"gopsql/pgio"
	"math"
)

const KindCopyFail byte = 'f'

var _ Message = &CopyFail{}
var _ Frontend = &CopyFail{}

type CopyFail struct {
	Message string
}

func (x *CopyFail) message() {}

func (x *CopyFail) frontend() {}

func (x *CopyFail) AppendBinary(b []byte) ([]byte, error) {
	sizeMessage := len(x.Message) + 1 // null terminated string
	length := sizeMessageLength + sizeMessage

	if length > math.MaxInt32 {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(KindCopyFail)
	buf.AppendInt32(int32(length))
	buf.AppendString(x.Message)
	return buf.Bytes(), nil
}

func (x *CopyFail) UnmarshalBinary(b []byte) error {
	kind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if kind != KindCopyFail {
		return unexpectedKind(kind, KindCopyFail)
	}

	m, b, err := pgio.ShiftString(b)
	if err != nil {
		return invalidFormat(err)
	}
	x.Message = m
	return nil
}

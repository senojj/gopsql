package pgwire

import (
	"gopsql/pgio"
	"math"
)

var _ Message = &SASLInitialResponse{}
var _ Frontend = &SASLInitialResponse{}

type SASLInitialResponse struct {
	Name     string
	Response []byte // will be nil when there is no initial response.
}

func (x *SASLInitialResponse) message() {}

func (x *SASLInitialResponse) frontend() {}

func (x *SASLInitialResponse) AppendBinary(b []byte) ([]byte, error) {
	const sizeMechanism = 4

	sizeName := len(x.Name) + 1 // null terminated string
	sizeResponse := len(x.Response)

	if sizeResponse > math.MaxInt32 {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	length := sizeMessageLength +
		sizeName +
		sizeMechanism +
		sizeResponse

	if length > math.MaxInt32 {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	buf := pgio.NewBuffer(b)

	buf.Grow(size)
	buf.AppendByte(byte(MsgSASLInitialResponse))
	buf.AppendInt32(int32(length))
	buf.AppendString(x.Name)
	buf.AppendInt32(int32(sizeResponse))
	buf.AppendByte(x.Response...)
	return buf.Bytes(), nil
}

func (x *SASLInitialResponse) UnmarshalBinary(b []byte) error {
	b, err := ShiftHeader(MsgSASLInitialResponse, b)
	if err != nil {
		return invalidFormat(err)
	}

	buf := pgio.NewBuffer(b)

	name, err := buf.ShiftString()
	if err != nil {
		return invalidFormat(err)
	}

	sizeResponse, err := buf.ShiftInt32()
	if err != nil {
		return invalidFormat(err)
	}

	response, err := buf.ShiftBytes(int(sizeResponse))
	if err != nil {
		return invalidFormat(err)
	}

	if buf.Len() > 0 {
		return invalidFormat(pgio.ErrValueOverflow)
	}

	x.Name = name
	x.Response = response
	return nil
}

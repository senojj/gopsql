package pgwire

import (
	"gopsql/pgio"
	"math"
)

const KindFunctionCallResponse byte = 'V'

var _ Message = &FunctionCallResponse{}
var _ Backend = &FunctionCallResponse{}

type FunctionCallResponse struct {
	// Can be zero length or nil.
	Result []byte
}

func (x *FunctionCallResponse) message() {}

func (x *FunctionCallResponse) backend() {}

func (x *FunctionCallResponse) AppendBinary(b []byte) ([]byte, error) {
	const sizeResultLength = 4
	sizeResult := len(x.Result)

	if sizeResult > math.MaxInt32 {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	length := sizeMessageLength +
		sizeResultLength +
		sizeResult

	size := sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(KindFunctionCallResponse)
	buf.AppendInt32(int32(length))

	if x.Result == nil {
		buf.AppendInt32(int32(-1))
	} else {
		buf.AppendInt32(int32(sizeResult))
	}
	buf.AppendByte(x.Result...)
	return buf.Bytes(), nil
}

func (x *FunctionCallResponse) UnmarshalBinary(b []byte) error {
	kind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if kind != KindFunctionCallResponse {
		return unexpectedKind(kind, KindFunctionCallResponse)
	}

	length, b, err := pgio.ShiftInt32(b)
	if err != nil {
		return invalidFormat(err)
	}

	if length >= 0 {
		x.Result = make([]byte, length)
		copy(x.Result, b)
	}
	// Result remains nil when length < 0
	return nil
}

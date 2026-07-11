package msg

import (
	"gopsql/internal/bytex"
	"math"
	"slices"
)

const KindFunctionCallResponse byte = 'V'

var _ Message = &FunctionCallResponse{}
var _ Backend = &FunctionCallResponse{}

type FunctionCallResponse struct {
	msg
	back

	// Can be zero length or nil.
	Result []byte
}

func (x *FunctionCallResponse) AppendBinary(b []byte) ([]byte, error) {
	const sizeResultLength = 4
	sizeResult := len(x.Result)

	if sizeResult > math.MaxInt32 {
		return nil, invalidFormat(bytex.ErrValueOverflow)
	}

	length := sizeMessageLength +
		sizeResultLength +
		sizeResult

	size := sizeMessageKind + length

	b = slices.Grow(b, size)
	b = bytex.AppendByte(b, KindFunctionCallResponse)
	b = bytex.AppendInt32(b, int32(length))

	if x.Result == nil {
		b = bytex.AppendInt32(b, int32(-1))
	} else {
		b = bytex.AppendInt32(b, int32(sizeResult))
	}
	b = bytex.AppendByte(b, x.Result...)
	return b, nil
}

func (x *FunctionCallResponse) UnmarshalBinary(b []byte) error {
	kind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if kind != KindFunctionCallResponse {
		return unexpectedKind(kind, KindFunctionCallResponse)
	}

	length, b, err := bytex.ShiftInt32(b)
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

package pgwire

import (
	"gopsql/pgio"
	"math"
)

var _ Message = &FunctionCall{}
var _ Frontend = &FunctionCall{}

type FunctionCall struct {
	ObjectID int32

	// ArgumentFormats may have zero elements, indicating that there are no
	// arguments, or that all arguments use the default format (text); or one,
	// in which case the specified format code is applied to all arguments; or
	// its element count may equal the total number of arguments.
	ArgumentFormats []int16

	ArgumentValues [][]byte
	ResultFormat   int16
}

func (x *FunctionCall) message() {}

func (x *FunctionCall) frontend() {}

func (x *FunctionCall) AppendBinary(b []byte) ([]byte, error) {
	const sizeObjectID = 4
	const sizeCountFormats = 2
	const sizeFormat = 2
	const sizeCountArguments = 2
	const sizeArgumentLength = 4
	const sizeResultFormat = 2

	countFormats := len(x.ArgumentFormats)

	if countFormats > math.MaxInt16 {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	countArguments := len(x.ArgumentValues)

	if countArguments > math.MaxInt16 {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	sizeFormats := countFormats * sizeFormat
	sizeArguments := 0

	for i := range countArguments {
		sizeArgumentValue := len(x.ArgumentValues[i])

		if sizeArgumentValue > math.MaxInt32 {
			return b, invalidFormat(pgio.ErrValueOverflow)
		}
		sizeArguments += sizeArgumentLength + sizeArgumentValue
	}

	length := sizeMessageLength +
		sizeObjectID +
		sizeCountFormats +
		sizeFormats +
		sizeCountArguments +
		sizeArguments +
		sizeResultFormat

	if length > math.MaxInt32 {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(byte(MsgFunctionCall))
	buf.AppendInt32(int32(length))
	buf.AppendInt32(x.ObjectID)
	buf.AppendInt16(int16(countFormats))
	buf.AppendInt16(x.ArgumentFormats...)
	buf.AppendInt16(int16(countArguments))

	for i := range countArguments {
		value := x.ArgumentValues[i]
		length := len(value)
		buf.AppendInt32(int32(length))
		buf.AppendByte(value...)
	}
	buf.AppendInt16(x.ResultFormat)
	return buf.Bytes(), nil
}

func (x *FunctionCall) UnmarshalBinary(b []byte) error {
	b, err := ShiftHeader(MsgFunctionCall, b)
	if err != nil {
		return invalidFormat(err)
	}

	buf := pgio.NewBuffer(b)

	objectID, err := buf.ShiftInt32()
	if err != nil {
		return invalidFormat(err)
	}

	countFormats, err := buf.ShiftInt16()
	if err != nil {
		return invalidFormat(err)
	}

	formats := make([]int16, 0, countFormats)
	for range countFormats {
		format, err := buf.ShiftInt16()
		if err != nil {
			return invalidFormat(err)
		}
		formats = append(formats, format)
	}

	countArguments, err := buf.ShiftInt16()
	if err != nil {
		return invalidFormat(err)
	}

	arguments := make([][]byte, 0, countArguments)
	for range countArguments {
		length, err := buf.ShiftInt32()
		if err != nil {
			return invalidFormat(err)
		}
		value, err := buf.ShiftBytes(int(length))
		if err != nil {
			return invalidFormat(err)
		}
		arguments = append(arguments, value)
	}
	resultFormat, err := buf.ShiftInt16()
	if err != nil {
		return invalidFormat(err)
	}
	x.ObjectID = objectID
	x.ArgumentFormats = formats
	x.ArgumentValues = arguments
	x.ResultFormat = resultFormat
	return nil
}

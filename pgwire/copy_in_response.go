package pgwire

import (
	"gopsql/pgio"
	"math"
)

var _ Message = &CopyInResponse{}
var _ Backend = &CopyInResponse{}

type CopyInResponse struct {
	Format  int8
	Columns []int16
}

func (x *CopyInResponse) message() {}

func (x *CopyInResponse) backend() {}

func (x *CopyInResponse) AppendBinary(b []byte) ([]byte, error) {
	const sizeFormat = 1
	const sizeColCount = 2
	const sizeCol = 2

	countCols := len(x.Columns)

	if countCols > math.MaxInt16 {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	sizeCols := countCols * sizeCol

	length := sizeMessageLength +
		sizeFormat +
		sizeColCount +
		sizeCols

	if length > math.MaxInt32 {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(byte(MsgCopyInResponse))
	buf.AppendInt32(int32(length))
	buf.AppendInt8(x.Format)
	buf.AppendInt16(int16(countCols))
	buf.AppendInt16(x.Columns...)
	return buf.Bytes(), nil
}

func (x *CopyInResponse) UnmarshalBinary(b []byte) error {
	b, err := ShiftHeader(MsgCopyInResponse, b)
	if err != nil {
		return invalidFormat(err)
	}

	buf := pgio.NewBuffer(b)

	format, err := buf.ShiftInt8()
	if err != nil {
		return invalidFormat(err)
	}

	length, err := buf.ShiftInt16()
	if err != nil {
		return invalidFormat(err)
	}

	columns := make([]int16, 0, length)

	for range length {
		value, err := buf.ShiftInt16()
		if err != nil {
			return invalidFormat(err)
		}
		columns = append(columns, value)
	}
	x.Format = format
	x.Columns = columns
	return nil
}

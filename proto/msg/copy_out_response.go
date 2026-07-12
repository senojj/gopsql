package msg

import (
	"gopsql/internal/bytex"
	"math"
)

const KindCopyOutResponse byte = 'H'

var _ Message = &CopyOutResponse{}
var _ Backend = &CopyOutResponse{}

type CopyOutResponse struct {
	Format  int8
	Columns []int16
}

func (x *CopyOutResponse) message() {}

func (x *CopyOutResponse) backend() {}

func (x *CopyOutResponse) AppendBinary(b []byte) ([]byte, error) {
	const sizeFormat = 1
	const sizeColCount = 2
	const sizeCol = 2

	countCols := len(x.Columns)

	if countCols > math.MaxInt16 {
		return b, invalidFormat(bytex.ErrValueOverflow)
	}

	sizeCols := countCols * sizeCol

	length := sizeMessageLength +
		sizeFormat +
		sizeColCount +
		sizeCols

	if length > math.MaxInt32 {
		return b, invalidFormat(bytex.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	buf := bytex.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(KindCopyOutResponse)
	buf.AppendInt32(int32(length))
	buf.AppendInt8(x.Format)
	buf.AppendInt16(int16(countCols))
	buf.AppendInt16(x.Columns...)
	return buf.Bytes(), nil
}

func (x *CopyOutResponse) UnmarshalBinary(b []byte) error {
	kind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if kind != KindCopyOutResponse {
		return unexpectedKind(kind, KindCopyOutResponse)
	}

	buf := bytex.NewBuffer(b)

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

package pgwire

import (
	"gopsql/pgio"
	"math"
)

var _ Message = &DataRow{}
var _ Backend = &DataRow{}

type DataRow struct {
	// First dimention is columns (can have 0 elements).
	// Second dimension is value data (can have 0 elements
	// or be nil).
	Columns [][]byte
}

func (x *DataRow) message() {}

func (x *DataRow) backend() {}

func (x *DataRow) AppendBinary(b []byte) ([]byte, error) {
	const sizeColCount = 2
	const sizeColLength = 4

	countCols := len(x.Columns)

	if countCols > math.MaxInt16 {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	sizeCols := 0

	for i := range countCols {
		lengthCol := len(x.Columns[i])

		if lengthCol > math.MaxInt32 {
			return b, invalidFormat(pgio.ErrValueOverflow)
		}
		sizeCols += sizeColLength + lengthCol
	}

	length := sizeMessageLength +
		sizeColCount +
		sizeCols

	if length > math.MaxInt32 {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(byte(MsgDataRow))
	buf.AppendInt32(int32(length))
	buf.AppendInt16(int16(countCols))

	for i := range countCols {
		column := x.Columns[i]
		if column == nil {
			buf.AppendInt32(-1)
			continue
		}
		lengthCol := len(column)
		buf.AppendInt32(int32(lengthCol))
		buf.AppendByte(column...)
	}
	return b, nil
}

func (x *DataRow) UnmarshalBinary(b []byte) error {
	b, err := ShiftHeader(MsgDataRow, b)
	if err != nil {
		return invalidFormat(err)
	}

	buf := pgio.NewBuffer(b)

	countCols, err := buf.ShiftInt16()
	if err != nil {
		return invalidFormat(err)
	}
	columns := make([][]byte, 0, countCols)

	for range countCols {
		length, err := buf.ShiftInt32()
		if err != nil {
			return invalidFormat(err)
		}

		if length == -1 {
			columns = append(columns, nil)
			continue
		}

		data, err := buf.ShiftBytes(int(length))
		if err != nil {
			return invalidFormat(err)
		}
		columns = append(columns, data)
	}

	x.Columns = columns
	return nil
}

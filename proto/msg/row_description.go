package msg

import (
	"gopsql/internal/bytex"
	"math"
)

const KindRowDescription byte = 'T'

var _ Message = &RowDescription{}
var _ Backend = &RowDescription{}

type RowDescription struct {
	Names     []string
	Tables    []int32
	Columns   []int16
	DataTypes []int32
	Sizes     []int16
	Modifiers []int32
	Formats   []int16
}

func (x *RowDescription) message() {}

func (x *RowDescription) backend() {}

func (x *RowDescription) AppendBinary(b []byte) ([]byte, error) {
	const (
		sizeFieldCount = 2
		sizeTable      = 4
		sizeColumn     = 2
		sizeDataType   = 4
		sizeSize       = 2
		sizeModifier   = 4
		sizeFormat     = 2

		sizeRowInvariant = sizeTable +
			sizeColumn +
			sizeDataType +
			sizeSize +
			sizeModifier +
			sizeFormat
	)

	countFields := len(x.Names)

	if countFields > math.MaxInt16 {
		return b, invalidFormat(bytex.ErrValueOverflow)
	}

	var sizeRows int

	for i := range countFields {
		sizeName := len(x.Names[i]) + 1 // null terminated string
		sizeRows += (sizeName + sizeRowInvariant)
	}

	length := sizeMessageLength + sizeFieldCount + sizeRows

	if length > math.MaxInt32 {
		return b, invalidFormat(bytex.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	buf := bytex.NewBuffer(b)

	buf.Grow(size)
	buf.AppendByte(KindRowDescription)
	buf.AppendInt32(int32(length))
	buf.AppendInt16(int16(countFields))

	for i := range countFields {
		buf.AppendString(x.Names[i])
		buf.AppendInt32(x.Tables[i])
		buf.AppendInt16(x.Columns[i])
		buf.AppendInt32(x.DataTypes[i])
		buf.AppendInt16(x.Sizes[i])
		buf.AppendInt32(x.Modifiers[i])
		buf.AppendInt16(x.Formats[i])
	}
	return buf.Bytes(), nil
}

func (x *RowDescription) UnmarshalBinary(b []byte) error {
	kind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if kind != KindRowDescription {
		return unexpectedKind(kind, KindRowDescription)
	}

	buf := bytex.NewBuffer(b)

	countFields, err := buf.ShiftInt16()
	if err != nil {
		return invalidFormat(err)
	}

	names := make([]string, 0, countFields)
	tables := make([]int32, 0, countFields)
	columns := make([]int16, 0, countFields)
	dataTypes := make([]int32, 0, countFields)
	sizes := make([]int16, 0, countFields)
	modifiers := make([]int32, 0, countFields)
	formats := make([]int16, 0, countFields)

	for range countFields {
		name, err := buf.ShiftString()
		if err != nil {
			return invalidFormat(err)
		}
		names = append(names, name)

		table, err := buf.ShiftInt32()
		if err != nil {
			return invalidFormat(err)
		}
		tables = append(tables, table)

		column, err := buf.ShiftInt16()
		if err != nil {
			return invalidFormat(err)
		}
		columns = append(columns, column)

		dataType, err := buf.ShiftInt32()
		if err != nil {
			return invalidFormat(err)
		}
		dataTypes = append(dataTypes, dataType)

		sz, err := buf.ShiftInt16()
		if err != nil {
			return invalidFormat(err)
		}
		sizes = append(sizes, sz)

		modifier, err := buf.ShiftInt32()
		if err != nil {
			return invalidFormat(err)
		}
		modifiers = append(modifiers, modifier)

		format, err := buf.ShiftInt16()
		if err != nil {
			return invalidFormat(err)
		}
		formats = append(formats, format)
	}

	x.Names = names
	x.Tables = tables
	x.Columns = columns
	x.DataTypes = dataTypes
	x.Sizes = sizes
	x.Modifiers = modifiers
	x.Formats = formats
	return nil
}

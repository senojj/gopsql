package pgwire

import (
	"gopsql/pgio"
	"math"
)

const KindBind byte = 'B'

var _ Message = &Bind{}
var _ Frontend = &Bind{}

type Bind struct {
	DestinationName      string
	SourceName           string
	ParameterFormatCodes []int16
	ParameterData        [][]byte
	ColumnFormatCodes    []int16
}

func (x *Bind) message() {}

func (x *Bind) frontend() {}

func (x *Bind) AppendBinary(b []byte) ([]byte, error) {
	const sizeParamFmtCodeCount = 2
	const sizeParamFmtCode = 2
	const sizeParamDataCount = 2
	const sizeParamDatum = 4
	const sizeColFmtCodeCount = 2
	const sizeColFmtCode = 2

	sizeDestinationName := len(x.DestinationName) + 1 // null terminated string
	sizeSourceName := len(x.SourceName) + 1           // null terminated string

	paramFmtCodeCount := len(x.ParameterFormatCodes)
	if paramFmtCodeCount > math.MaxInt16 {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	sizeParamFmtCodes := paramFmtCodeCount * sizeParamFmtCode

	paramDataCount := len(x.ParameterData)
	if paramDataCount > math.MaxInt16 {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	sizeParamData := 0

	for i := range paramDataCount {
		length := len(x.ParameterData[i])
		if length > math.MaxInt32 {
			return b, invalidFormat(pgio.ErrValueOverflow)
		}
		sizeParamData += sizeParamDatum + length // size prefixed
	}

	colFmtCodeCount := len(x.ColumnFormatCodes)
	if colFmtCodeCount > math.MaxInt16 {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	sizeColFmtCodes := colFmtCodeCount * sizeColFmtCode

	length := sizeMessageLength +
		sizeDestinationName +
		sizeSourceName +
		sizeParamFmtCodeCount +
		sizeParamFmtCodes +
		sizeParamDataCount +
		sizeParamData +
		sizeColFmtCodeCount +
		sizeColFmtCodes

	if length > math.MaxInt32 {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(KindBind)
	buf.AppendInt32(int32(length))
	buf.AppendString(x.DestinationName)
	buf.AppendString(x.SourceName)
	buf.AppendInt16(int16(paramFmtCodeCount))
	buf.AppendInt16(x.ParameterFormatCodes...)
	buf.AppendInt16(int16(paramDataCount))

	for i := range paramDataCount {
		sizeData := len(x.ParameterData[i])
		buf.AppendInt32(int32(sizeData))
		buf.AppendByte(x.ParameterData[i]...)
	}

	buf.AppendInt16(int16(colFmtCodeCount))
	buf.AppendInt16(x.ColumnFormatCodes...)
	return buf.Bytes(), nil
}

func (x *Bind) UnmarshalBinary(b []byte) error {
	kind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if kind != KindBind {
		return unexpectedKind(kind, KindBind)
	}

	buf := pgio.NewBuffer(b)

	destination, err := buf.ShiftString()
	if err != nil {
		return invalidFormat(err)
	}

	source, err := buf.ShiftString()
	if err != nil {
		return invalidFormat(err)
	}

	paramFmtCodeCount, err := buf.ShiftInt16()
	if err != nil {
		return invalidFormat(err)
	}
	parameterFormatCodes := make([]int16, paramFmtCodeCount)

	for i := range paramFmtCodeCount {
		code, err := buf.ShiftInt16()
		if err != nil {
			return invalidFormat(err)
		}
		parameterFormatCodes[i] = code
	}

	paramDataCount, err := buf.ShiftInt16()
	if err != nil {
		return invalidFormat(err)
	}
	parameterData := make([][]byte, paramDataCount)

	for i := range paramDataCount {
		dataLen, err := buf.ShiftInt32()
		if err != nil {
			return invalidFormat(err)
		}

		data, err := buf.ShiftBytes(int(dataLen))
		if err != nil {
			return invalidFormat(err)
		}
		parameterData[i] = data
	}

	colFmtCodeCount, err := buf.ShiftInt16()
	if err != nil {
		return invalidFormat(err)
	}
	columnFormatCodes := make([]int16, colFmtCodeCount)

	for i := range colFmtCodeCount {
		data, err := buf.ShiftInt16()
		if err != nil {
			return invalidFormat(err)
		}
		columnFormatCodes[i] = data
	}

	if buf.Len() > 0 {
		return invalidFormat(pgio.ErrValueOverflow)
	}

	x.DestinationName = destination
	x.SourceName = source
	x.ParameterFormatCodes = parameterFormatCodes
	x.ParameterData = parameterData
	x.ColumnFormatCodes = columnFormatCodes
	return nil
}

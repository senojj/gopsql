package pgwire

import (
	"gopsql/pgio"
	"math"
)

var _ Message = &MsgBackendKeyData{}
var _ Backend = &MsgBackendKeyData{}

type MsgBackendKeyData struct {
	ProcessID int32
	SecretKey []byte
}

func (x *MsgBackendKeyData) message() {}

func (x *MsgBackendKeyData) backend() {}

func (x *MsgBackendKeyData) AppendBinary(b []byte) ([]byte, error) {
	const sizeProcessID = 4
	sizeSecretKey := len(x.SecretKey)

	if sizeSecretKey < 4 {
		return b, invalidFormat(pgio.ErrValueUnderflow)
	}

	if sizeSecretKey > 256 {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	length := sizeMessageLength + sizeProcessID + sizeSecretKey

	if length > math.MaxInt32 {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(byte(MessageKindBackendKeyData))
	buf.AppendInt32(int32(length))
	buf.AppendInt32(x.ProcessID)
	buf.AppendByte(x.SecretKey...)
	return buf.Bytes(), nil
}

func (x *MsgBackendKeyData) UnmarshalBinary(b []byte) error {
	b, err := shiftHeader(MessageKindBackendKeyData, b)
	if err != nil {
		return invalidFormat(err)
	}

	buf := pgio.NewBuffer(b)

	processID, err := buf.ShiftInt32()
	if err != nil {
		return invalidFormat(err)
	}

	if buf.Len() < 4 {
		return invalidFormat(pgio.ErrValueUnderflow)
	}

	if buf.Len() > 256 {
		return invalidFormat(pgio.ErrValueOverflow)
	}
	secretKey := make([]byte, buf.Len())
	copy(secretKey, buf.Bytes())

	x.ProcessID = processID
	x.SecretKey = secretKey
	return nil
}

var _ Message = &MsgBindComplete{}
var _ Backend = &MsgBindComplete{}

type MsgBindComplete struct{}

func (x *MsgBindComplete) message() {}

func (x *MsgBindComplete) backend() {}

func (x *MsgBindComplete) AppendBinary(b []byte) ([]byte, error) {
	const length = sizeMessageLength
	const size = sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(byte(MessageKindBindComplete))
	buf.AppendInt32(int32(length))
	return buf.Bytes(), nil
}

func (x *MsgBindComplete) UnmarshalBinary(b []byte) error {
	b, err := shiftHeader(MessageKindBindComplete, b)
	if err != nil {
		return invalidFormat(err)
	}

	if len(b) > 0 {
		return invalidFormat(pgio.ErrValueOverflow)
	}
	return nil
}

var _ Message = &MsgCloseComplete{}
var _ Backend = &MsgCloseComplete{}

type MsgCloseComplete struct{}

func (x *MsgCloseComplete) message() {}

func (x *MsgCloseComplete) backend() {}

func (x *MsgCloseComplete) AppendBinary(b []byte) ([]byte, error) {
	const length = sizeMessageLength
	const size = sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(byte(MessageKindCloseComplete))
	buf.AppendInt32(int32(length))
	return buf.Bytes(), nil
}

func (x *MsgCloseComplete) UnmarshalBinary(b []byte) error {
	b, err := shiftHeader(MessageKindCloseComplete, b)
	if err != nil {
		return invalidFormat(err)
	}

	if len(b) > 0 {
		return invalidFormat(pgio.ErrValueOverflow)
	}
	return nil
}

var _ Message = &MsgCommandComplete{}
var _ Backend = &MsgCommandComplete{}

type MsgCommandComplete struct {
	Tag string
}

func (x *MsgCommandComplete) message() {}

func (x *MsgCommandComplete) backend() {}

func (x *MsgCommandComplete) AppendBinary(b []byte) ([]byte, error) {
	sizeTag := len(x.Tag) + 1 // null terminated string
	length := sizeMessageLength + sizeTag

	if length > math.MaxInt32 {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(byte(MessageKindCommandComplete))
	buf.AppendInt32(int32(length))
	buf.AppendString(x.Tag)
	return buf.Bytes(), nil
}

func (x *MsgCommandComplete) UnmarshalBinary(b []byte) error {
	b, err := shiftHeader(MessageKindCommandComplete, b)
	if err != nil {
		return invalidFormat(err)
	}

	buf := pgio.NewBuffer(b)

	tag, err := buf.ShiftString()
	if err != nil {
		return invalidFormat(err)
	}
	x.Tag = tag
	return nil
}

var _ Message = &MsgCopyInResponse{}
var _ Backend = &MsgCopyInResponse{}

type MsgCopyInResponse struct {
	Format  int8
	Columns []int16
}

func (x *MsgCopyInResponse) message() {}

func (x *MsgCopyInResponse) backend() {}

func (x *MsgCopyInResponse) AppendBinary(b []byte) ([]byte, error) {
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
	buf.AppendByte(byte(MessageKindCopyInResponse))
	buf.AppendInt32(int32(length))
	buf.AppendInt8(x.Format)
	buf.AppendInt16(int16(countCols))
	buf.AppendInt16(x.Columns...)
	return buf.Bytes(), nil
}

func (x *MsgCopyInResponse) UnmarshalBinary(b []byte) error {
	b, err := shiftHeader(MessageKindCopyInResponse, b)
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

var _ Message = &MsgCopyOutResponse{}
var _ Backend = &MsgCopyOutResponse{}

type MsgCopyOutResponse struct {
	Format  int8
	Columns []int16
}

func (x *MsgCopyOutResponse) message() {}

func (x *MsgCopyOutResponse) backend() {}

func (x *MsgCopyOutResponse) AppendBinary(b []byte) ([]byte, error) {
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
	buf.AppendByte(byte(MessageKindCopyOutResponse))
	buf.AppendInt32(int32(length))
	buf.AppendInt8(x.Format)
	buf.AppendInt16(int16(countCols))
	buf.AppendInt16(x.Columns...)
	return buf.Bytes(), nil
}

func (x *MsgCopyOutResponse) UnmarshalBinary(b []byte) error {
	b, err := shiftHeader(MessageKindCopyOutResponse, b)
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

var _ Message = &MsgCopyBothResponse{}
var _ Backend = &MsgCopyBothResponse{}

type MsgCopyBothResponse struct {
	Format  int8
	Columns []int16
}

func (x *MsgCopyBothResponse) message() {}

func (x *MsgCopyBothResponse) backend() {}

func (x *MsgCopyBothResponse) AppendBinary(b []byte) ([]byte, error) {
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
	buf.AppendByte(byte(MessageKindCopyBothResponse))
	buf.AppendInt32(int32(length))
	buf.AppendInt8(x.Format)
	buf.AppendInt16(int16(countCols))
	buf.AppendInt16(x.Columns...)
	return buf.Bytes(), nil
}

func (x *MsgCopyBothResponse) UnmarshalBinary(b []byte) error {
	b, err := shiftHeader(MessageKindCopyBothResponse, b)
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

var _ Message = &MsgDataRow{}
var _ Backend = &MsgDataRow{}

type MsgDataRow struct {
	// First dimention is columns (can have 0 elements).
	// Second dimension is value data (can have 0 elements
	// or be nil).
	Columns [][]byte
}

func (x *MsgDataRow) message() {}

func (x *MsgDataRow) backend() {}

func (x *MsgDataRow) AppendBinary(b []byte) ([]byte, error) {
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
	buf.AppendByte(byte(MessageKindDataRow))
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

func (x *MsgDataRow) UnmarshalBinary(b []byte) error {
	b, err := shiftHeader(MessageKindDataRow, b)
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

var _ Message = &MsgEmptyQueryResponse{}
var _ Backend = &MsgEmptyQueryResponse{}

type MsgEmptyQueryResponse struct{}

func (x *MsgEmptyQueryResponse) message() {}

func (x *MsgEmptyQueryResponse) backend() {}

func (x *MsgEmptyQueryResponse) AppendBinary(b []byte) ([]byte, error) {
	const length = sizeMessageLength
	const size = sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(byte(MessageKindEmptyQueryResponse))
	buf.AppendInt32(int32(length))
	return buf.Bytes(), nil
}

func (x *MsgEmptyQueryResponse) UnmarshalBinary(b []byte) error {
	b, err := shiftHeader(MessageKindEmptyQueryResponse, b)
	if err != nil {
		return invalidFormat(err)
	}

	if len(b) > 0 {
		return invalidFormat(pgio.ErrValueOverflow)
	}
	return nil
}

var _ Message = &MsgErrorResponse{}
var _ Backend = &MsgErrorResponse{}

type MsgErrorResponse struct {
	Fields []byte
	Values []string
}

func (x *MsgErrorResponse) message() {}

func (x *MsgErrorResponse) backend() {}

func (x *MsgErrorResponse) AppendBinary(b []byte) ([]byte, error) {
	const sizeField = 1

	countFields := len(x.Fields)
	countValues := len(x.Values)

	sizeFields := countFields * sizeField

	length := sizeMessageLength + sizeFields

	for i := range countValues {
		value := x.Values[i]
		length += len(value) + 1 // null terminated string
	}

	length += 1 // null terminated list

	if length > math.MaxInt32 {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(byte(MessageKindErrorResponse))
	buf.AppendInt32(int32(length))

	for i := range countFields {
		buf.AppendByte(x.Fields[i])
		buf.AppendString(x.Values[i])
	}
	buf.AppendByte(0)
	return b, nil
}

func (x *MsgErrorResponse) UnmarshalBinary(b []byte) error {
	b, err := shiftHeader(MessageKindErrorResponse, b)
	if err != nil {
		return invalidFormat(err)
	}

	buf := pgio.NewBuffer(b)

	var fields []byte
	var values []string

	field, err := buf.ShiftByte()
	if err != nil {
		return invalidFormat(err)
	}

	for field != 0 {
		fields = append(fields, field)

		value, err := buf.ShiftString()
		if err != nil {
			return invalidFormat(err)
		}
		values = append(values, value)

		field, err = buf.ShiftByte()
		if err != nil {
			return invalidFormat(err)
		}
	}

	x.Fields = fields
	x.Values = values
	return nil
}

var _ Message = &MsgFunctionCallResponse{}
var _ Backend = &MsgFunctionCallResponse{}

type MsgFunctionCallResponse struct {
	// Can be zero length or nil.
	Result []byte
}

func (x *MsgFunctionCallResponse) message() {}

func (x *MsgFunctionCallResponse) backend() {}

func (x *MsgFunctionCallResponse) AppendBinary(b []byte) ([]byte, error) {
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
	buf.AppendByte(byte(MessageKindFunctionCallResponse))
	buf.AppendInt32(int32(length))

	if x.Result == nil {
		buf.AppendInt32(int32(-1))
	} else {
		buf.AppendInt32(int32(sizeResult))
	}
	buf.AppendByte(x.Result...)
	return buf.Bytes(), nil
}

func (x *MsgFunctionCallResponse) UnmarshalBinary(b []byte) error {
	b, err := shiftHeader(MessageKindFunctionCallResponse, b)
	if err != nil {
		return invalidFormat(err)
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

var _ Message = &MsgNegotiateProtocolVersion{}
var _ Backend = &MsgNegotiateProtocolVersion{}

type MsgNegotiateProtocolVersion struct {
	MinorVersionSupported int32
	UnrecognizedOptions   []string
}

func (x *MsgNegotiateProtocolVersion) message() {}

func (x *MsgNegotiateProtocolVersion) backend() {}

func (x *MsgNegotiateProtocolVersion) AppendBinary(b []byte) ([]byte, error) {
	const sizeMinorVersion = 4
	const sizeUnrecognizedOptionCount = 4

	length := sizeMessageLength +
		sizeMinorVersion +
		sizeUnrecognizedOptionCount

	countUnrecognizedOptions := len(x.UnrecognizedOptions)

	if countUnrecognizedOptions > math.MaxInt32 {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	for _, option := range x.UnrecognizedOptions {
		length += len(option)
	}

	if length > math.MaxInt32 {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(byte(MessageKindNegotiateProtocolVersion))
	buf.AppendInt32(int32(length))
	buf.AppendInt32(x.MinorVersionSupported)
	buf.AppendInt32(int32(countUnrecognizedOptions))
	buf.AppendString(x.UnrecognizedOptions...)
	return buf.Bytes(), nil
}

func (x *MsgNegotiateProtocolVersion) UnmarshalBinary(b []byte) error {
	b, err := shiftHeader(MessageKindNegotiateProtocolVersion, b)
	if err != nil {
		return invalidFormat(err)
	}

	buf := pgio.NewBuffer(b)

	minorVersion, err := buf.ShiftInt32()
	if err != nil {
		return invalidFormat(err)
	}

	countUnsupportedOptions, err := buf.ShiftInt32()
	if err != nil {
		return invalidFormat(err)
	}

	options := make([]string, 0, countUnsupportedOptions)

	for range countUnsupportedOptions {
		option, err := buf.ShiftString()
		if err != nil {
			return invalidFormat(err)
		}
		options = append(options, option)
	}
	x.MinorVersionSupported = minorVersion
	x.UnrecognizedOptions = options
	return nil
}

var _ Message = &MsgNoData{}
var _ Backend = &MsgNoData{}

type MsgNoData struct{}

func (x *MsgNoData) message() {}

func (x *MsgNoData) backend() {}

func (x *MsgNoData) AppendBinary(b []byte) ([]byte, error) {
	const length = sizeMessageLength
	const size = sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(byte(MessageKindNoData))
	buf.AppendInt32(length)
	return buf.Bytes(), nil
}

func (x *MsgNoData) UnmarshalBinary(b []byte) error {
	b, err := shiftHeader(MessageKindNoData, b)
	if err != nil {
		return invalidFormat(err)
	}

	if len(b) > 0 {
		return invalidFormat(pgio.ErrValueOverflow)
	}
	return nil
}

var _ Message = &MsgNoticeResponse{}
var _ Backend = &MsgNoticeResponse{}

type MsgNoticeResponse struct {
	Fields []byte
	Values []string
}

func (x *MsgNoticeResponse) message() {}

func (x *MsgNoticeResponse) backend() {}

func (x *MsgNoticeResponse) AppendBinary(b []byte) ([]byte, error) {
	countFields := len(x.Fields)

	if countFields != len(x.Values) {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	length := sizeMessageLength + countFields

	for _, value := range x.Values {
		length += len(value) + 1 // null terminated strings
	}
	length += 1 // null terminated list

	if length > math.MaxInt32 {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(byte(MessageKindNoticeResponse))
	buf.AppendInt32(int32(length))

	for i := range countFields {
		buf.AppendByte(x.Fields[i])
		buf.AppendString(x.Values[i])
	}
	buf.AppendByte(0)
	return buf.Bytes(), nil
}

func (x *MsgNoticeResponse) UnmarshalBinary(b []byte) error {
	b, err := shiftHeader(MessageKindNoticeResponse, b)
	if err != nil {
		return invalidFormat(err)
	}

	buf := pgio.NewBuffer(b)

	field, err := buf.ShiftByte()
	if err != nil {
		return invalidFormat(err)
	}

	var fields []byte
	var values []string

	for field != 0 {
		fields = append(fields, field)

		value, err := buf.ShiftString()
		if err != nil {
			return invalidFormat(err)
		}
		values = append(values, value)

		field, err = buf.ShiftByte()
		if err != nil {
			return invalidFormat(err)
		}
	}
	x.Fields = fields
	x.Values = values
	return nil
}

var _ Message = &MsgNotificationResponse{}
var _ Backend = &MsgNotificationResponse{}

type MsgNotificationResponse struct {
	ProcessID int32
	Channel   string
	Payload   string
}

func (x *MsgNotificationResponse) message() {}

func (x *MsgNotificationResponse) backend() {}

func (x *MsgNotificationResponse) AppendBinary(b []byte) ([]byte, error) {
	const sizeProcessID = 4

	sizeChannel := len(x.Channel) + 1 // null terminated string
	sizePayload := len(x.Payload) + 1 // null terminated string

	length := sizeMessageLength +
		sizeProcessID +
		sizeChannel +
		sizePayload

	if length > math.MaxInt32 {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(byte(MessageKindNotificationResponse))
	buf.AppendInt32(int32(length))
	buf.AppendString(x.Channel)
	buf.AppendString(x.Payload)
	return buf.Bytes(), nil
}

func (x *MsgNotificationResponse) UnmarshalBinary(b []byte) error {
	b, err := shiftHeader(MessageKindNotificationResponse, b)
	if err != nil {
		return invalidFormat(err)
	}

	buf := pgio.NewBuffer(b)

	processID, err := buf.ShiftInt32()
	if err != nil {
		return invalidFormat(err)
	}

	channel, err := buf.ShiftString()
	if err != nil {
		return invalidFormat(err)
	}

	payload, err := buf.ShiftString()
	if err != nil {
		return invalidFormat(err)
	}

	x.ProcessID = processID
	x.Channel = channel
	x.Payload = payload
	return nil
}

var _ Message = &MsgParameterDescription{}
var _ Backend = &MsgParameterDescription{}

type MsgParameterDescription struct {
	Parameters []int32
}

func (x *MsgParameterDescription) message() {}

func (x *MsgParameterDescription) backend() {}

func (x *MsgParameterDescription) AppendBinary(b []byte) ([]byte, error) {
	const sizeParameterCount = 2
	const sizeParameter = 4

	countParameter := len(x.Parameters)

	length := sizeMessageLength +
		sizeParameterCount +
		sizeParameter*countParameter

	if length > math.MaxInt32 {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(byte(MessageKindParameterDescription))
	buf.AppendInt32(int32(length))
	buf.AppendInt16(int16(countParameter))

	for i := range countParameter {
		buf.AppendInt32(x.Parameters[i])
	}
	return buf.Bytes(), nil
}

func (x *MsgParameterDescription) UnmarshalBinary(b []byte) error {
	b, err := shiftHeader(MessageKindParameterDescription, b)
	if err != nil {
		return invalidFormat(err)
	}

	buf := pgio.NewBuffer(b)

	countParameters, err := buf.ShiftInt16()
	if err != nil {
		return invalidFormat(err)
	}

	parameters := make([]int32, 0, countParameters)
	for range countParameters {
		parameter, err := buf.ShiftInt32()
		if err != nil {
			return invalidFormat(err)
		}
		parameters = append(parameters, parameter)
	}
	x.Parameters = parameters
	return nil
}

var _ Message = &MsgParameterStatus{}
var _ Backend = &MsgParameterStatus{}

type MsgParameterStatus struct {
	Name  string
	Value string
}

func (x *MsgParameterStatus) message() {}

func (x *MsgParameterStatus) backend() {}

func (x *MsgParameterStatus) AppendBinary(b []byte) ([]byte, error) {
	sizeName := len(x.Name) + 1   // null terminated string
	sizeValue := len(x.Value) + 1 // null terminated string

	length := sizeMessageLength +
		sizeName +
		sizeValue

	if length > math.MaxInt32 {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	buf := pgio.NewBuffer(b)

	buf.Grow(size)
	buf.AppendByte(byte(MessageKindParameterStatus))
	buf.AppendInt32(int32(length))
	buf.AppendString(x.Name)
	buf.AppendString(x.Value)
	return buf.Bytes(), nil
}

func (x *MsgParameterStatus) UnmarshalBinary(b []byte) error {
	b, err := shiftHeader(MessageKindParameterStatus, b)
	if err != nil {
		return invalidFormat(err)
	}

	buf := pgio.NewBuffer(b)

	name, err := buf.ShiftString()
	if err != nil {
		return invalidFormat(err)
	}

	value, err := buf.ShiftString()
	if err != nil {
		return invalidFormat(err)
	}

	x.Name = name
	x.Value = value
	return nil
}

var _ Message = &MsgParseComplete{}
var _ Backend = &MsgParseComplete{}

type MsgParseComplete struct{}

func (x *MsgParseComplete) message() {}

func (x *MsgParseComplete) backend() {}

func (x *MsgParseComplete) AppendBinary(b []byte) ([]byte, error) {
	const length = sizeMessageLength
	const size = sizeMessageKind + length

	buf := pgio.NewBuffer(b)

	buf.Grow(size)
	buf.AppendByte(byte(MessageKindParseComplete))
	buf.AppendInt32(int32(length))
	return buf.Bytes(), nil
}

func (x *MsgParseComplete) UnmarshalBinary(b []byte) error {
	b, err := shiftHeader(MessageKindParseComplete, b)
	if err != nil {
		return invalidFormat(err)
	}

	if len(b) > 0 {
		return invalidFormat(pgio.ErrValueOverflow)
	}
	return nil
}

var _ Message = &MsgPortalSuspended{}
var _ Backend = &MsgPortalSuspended{}

type MsgPortalSuspended struct{}

func (x *MsgPortalSuspended) message() {}

func (x *MsgPortalSuspended) backend() {}

func (x *MsgPortalSuspended) AppendBinary(b []byte) ([]byte, error) {
	const length = sizeMessageLength
	const size = sizeMessageKind + length

	buf := pgio.NewBuffer(b)

	buf.Grow(size)
	buf.AppendByte(byte(MessageKindPortalSuspend))
	buf.AppendInt32(int32(length))
	return buf.Bytes(), nil
}

func (x *MsgPortalSuspended) UnmarshalBinary(b []byte) error {
	b, err := shiftHeader(MessageKindPortalSuspend, b)
	if err != nil {
		return invalidFormat(err)
	}

	if len(b) > 0 {
		return invalidFormat(pgio.ErrValueOverflow)
	}
	return nil
}

var _ Message = &MsgReadyForQuery{}
var _ Backend = &MsgReadyForQuery{}

type MsgReadyForQuery struct {
	TxStatus byte
}

func (x *MsgReadyForQuery) message() {}

func (x *MsgReadyForQuery) backend() {}

func (x *MsgReadyForQuery) AppendBinary(b []byte) ([]byte, error) {
	const sizeTxStatus = 1
	const length = sizeMessageLength + sizeTxStatus
	const size = sizeMessageKind + length

	buf := pgio.NewBuffer(b)

	buf.Grow(size)
	buf.AppendByte(byte(MessageKindReadyForQuery))
	buf.AppendInt32(int32(length))
	buf.AppendByte(x.TxStatus)
	return buf.Bytes(), nil
}

func (x *MsgReadyForQuery) UnmarshalBinary(b []byte) error {
	b, err := shiftHeader(MessageKindReadyForQuery, b)
	if err != nil {
		return invalidFormat(err)
	}

	status, b, err := pgio.ShiftByte(b)
	if err != nil {
		return invalidFormat(err)
	}

	if len(b) > 0 {
		return invalidFormat(pgio.ErrValueOverflow)
	}

	x.TxStatus = status
	return nil
}

var _ Message = &MsgRowDescription{}
var _ Backend = &MsgRowDescription{}

type MsgRowDescription struct {
	Names     []string
	Tables    []int32
	Columns   []int16
	DataTypes []int32
	Sizes     []int16
	Modifiers []int32
	Formats   []int16
}

func (x *MsgRowDescription) message() {}

func (x *MsgRowDescription) backend() {}

func (x *MsgRowDescription) AppendBinary(b []byte) ([]byte, error) {
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
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	var sizeRows int

	for i := range countFields {
		sizeName := len(x.Names[i]) + 1 // null terminated string
		sizeRows += (sizeName + sizeRowInvariant)
	}

	length := sizeMessageLength + sizeFieldCount + sizeRows

	if length > math.MaxInt32 {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	buf := pgio.NewBuffer(b)

	buf.Grow(size)
	buf.AppendByte(byte(MessageKindRowDescription))
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

func (x *MsgRowDescription) UnmarshalBinary(b []byte) error {
	b, err := shiftHeader(MessageKindRowDescription, b)
	if err != nil {
		return invalidFormat(err)
	}

	buf := pgio.NewBuffer(b)

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

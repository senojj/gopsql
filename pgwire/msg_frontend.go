package pgwire

import (
	"gopsql/pgio"
	"math"
)

var _ Message = &MsgBind{}
var _ Frontend = &MsgBind{}

type MsgBind struct {
	DestinationName      string
	SourceName           string
	ParameterFormatCodes []FormatKind
	ParameterData        [][]byte
	ColumnFormatCodes    []FormatKind
}

func (x *MsgBind) message() {}

func (x *MsgBind) frontend() {}

func (x *MsgBind) AppendBinary(b []byte) ([]byte, error) {
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
	buf.AppendByte(byte(MessageKindBind))
	buf.AppendInt32(int32(length))
	buf.AppendString(x.DestinationName)
	buf.AppendString(x.SourceName)
	buf.AppendInt16(int16(paramFmtCodeCount))

	for _, format := range x.ParameterFormatCodes {
		buf.AppendInt16(int16(format))
	}
	buf.AppendInt16(int16(paramDataCount))

	for i := range paramDataCount {
		sizeData := len(x.ParameterData[i])
		buf.AppendInt32(int32(sizeData))
		buf.AppendByte(x.ParameterData[i]...)
	}

	buf.AppendInt16(int16(colFmtCodeCount))

	for _, format := range x.ColumnFormatCodes {
		buf.AppendInt16(int16(format))
	}
	return buf.Bytes(), nil
}

func (x *MsgBind) UnmarshalBinary(b []byte) error {
	b, err := shiftHeader(MessageKindBind, b)
	if err != nil {
		return invalidFormat(err)
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
	parameterFormatCodes := make([]FormatKind, paramFmtCodeCount)

	for i := range paramFmtCodeCount {
		code, err := buf.ShiftInt16()
		if err != nil {
			return invalidFormat(err)
		}
		parameterFormatCodes[i] = FormatKind(code)
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
	columnFormatCodes := make([]FormatKind, colFmtCodeCount)

	for i := range colFmtCodeCount {
		data, err := buf.ShiftInt16()
		if err != nil {
			return invalidFormat(err)
		}
		columnFormatCodes[i] = FormatKind(data)
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

var _ Message = &MsgCancelRequest{}
var _ Frontend = &MsgCancelRequest{}

type MsgCancelRequest struct {
	ProcessID int32
	SecretKey []byte
}

func (x *MsgCancelRequest) message() {}

func (x *MsgCancelRequest) frontend() {}

func (x *MsgCancelRequest) AppendBinary(b []byte) ([]byte, error) {
	const sizeCode = 4
	const sizeProcessID = 4

	sizeSecretKey := len(x.SecretKey)

	if sizeSecretKey > 256 {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	if sizeSecretKey < 4 {
		return b, invalidFormat(pgio.ErrValueUnderflow)
	}

	length := sizeMessageLength +
		sizeCode +
		sizeProcessID +
		sizeSecretKey

	buf := pgio.NewBuffer(b)
	buf.Grow(length)
	buf.AppendInt32(int32(length))
	buf.AppendInt32(CodeCancelRequest)
	buf.AppendInt32(x.ProcessID)
	buf.AppendByte(x.SecretKey...)
	return buf.Bytes(), nil
}

func (x *MsgCancelRequest) UnmarshalBinary(b []byte) error {
	b, err := shiftLength(b)
	if err != nil {
		return invalidFormat(err)
	}

	buf := pgio.NewBuffer(b)

	code, err := buf.ShiftInt32()
	if err != nil {
		return invalidFormat(err)
	}

	if code != CodeCancelRequest {
		return invalidFormat(pgio.ErrUnknownCode)
	}

	processID, err := buf.ShiftInt32()
	if err != nil {
		return err
	}

	x.ProcessID = processID
	x.SecretKey = make([]byte, buf.Len())
	copy(x.SecretKey, buf.Bytes())
	return nil
}

var _ Message = &MsgClose{}
var _ Frontend = &MsgClose{}

type MsgClose struct {
	ObjectKind ObjectKind
	ObjectName string
}

func (x *MsgClose) message() {}

func (x *MsgClose) frontend() {}

func (x *MsgClose) AppendBinary(b []byte) ([]byte, error) {
	const sizeKind = 1

	sizeName := len(x.ObjectName) + 1 // null terminated string

	length := sizeMessageLength + sizeKind + sizeName

	if length > math.MaxInt32 {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(byte(MessageKindClose))
	buf.AppendInt32(int32(length))
	buf.AppendByte(byte(x.ObjectKind))
	buf.AppendString(x.ObjectName)
	return buf.Bytes(), nil
}

func (x *MsgClose) UnmarshalBinary(b []byte) error {
	b, err := shiftHeader(MessageKindClose, b)
	if err != nil {
		return invalidFormat(err)
	}

	buf := pgio.NewBuffer(b)

	kind, err := buf.ShiftByte()
	if err != nil {
		return invalidFormat(err)
	}

	name, err := buf.ShiftString()
	if err != nil {
		return invalidFormat(err)
	}
	x.ObjectKind = ObjectKind(kind)
	x.ObjectName = name
	return nil
}

var _ Message = &MsgCopyFail{}
var _ Frontend = &MsgCopyFail{}

type MsgCopyFail struct {
	Message string
}

func (x *MsgCopyFail) message() {}

func (x *MsgCopyFail) frontend() {}

func (x *MsgCopyFail) AppendBinary(b []byte) ([]byte, error) {
	sizeMessage := len(x.Message) + 1 // null terminated string
	length := sizeMessageLength + sizeMessage

	if length > math.MaxInt32 {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(byte(MessageKindCopyFail))
	buf.AppendInt32(int32(length))
	buf.AppendString(x.Message)
	return buf.Bytes(), nil
}

func (x *MsgCopyFail) UnmarshalBinary(b []byte) error {
	b, err := shiftHeader(MessageKindCopyFail, b)
	if err != nil {
		return invalidFormat(err)
	}

	m, b, err := pgio.ShiftString(b)
	if err != nil {
		return invalidFormat(err)
	}

	if len(b) > 0 {
		return invalidFormat(pgio.ErrValueOverflow)
	}
	x.Message = m
	return nil
}

var _ Message = &MsgDescribe{}
var _ Frontend = &MsgDescribe{}

type MsgDescribe struct {
	ObjectKind ObjectKind
	ObjectName string
}

func (x *MsgDescribe) message() {}

func (x *MsgDescribe) frontend() {}

func (x *MsgDescribe) AppendBinary(b []byte) ([]byte, error) {
	const sizeKind = 1

	length := sizeMessageLength +
		sizeKind +
		len(x.ObjectName) + 1 // null terminated string

	if length > math.MaxInt32 {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(byte(MessageKindDescribe))
	buf.AppendInt32(int32(length))
	buf.AppendByte(byte(x.ObjectKind))
	buf.AppendString(x.ObjectName)
	return buf.Bytes(), nil
}

func (x *MsgDescribe) UnmarshalBinary(b []byte) error {
	b, err := shiftHeader(MessageKindDescribe, b)
	if err != nil {
		return invalidFormat(err)
	}

	buf := pgio.NewBuffer(b)

	kind, err := buf.ShiftByte()
	if err != nil {
		return invalidFormat(err)
	}

	name, err := buf.ShiftString()
	if err != nil {
		return invalidFormat(err)
	}

	x.ObjectKind = ObjectKind(kind)
	x.ObjectName = name
	return nil
}

var _ Message = &MsgExecute{}
var _ Frontend = &MsgExecute{}

type MsgExecute struct {
	PortalName string
	RowLimit   int32
}

func (x *MsgExecute) message() {}

func (x *MsgExecute) frontend() {}

func (x *MsgExecute) AppendBinary(b []byte) ([]byte, error) {
	const sizeRowLimit = 4

	sizePortal := len(x.PortalName) + 1 // null terminated string

	length := sizeMessageLength + sizePortal + sizeRowLimit

	if length > math.MaxInt32 {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(byte(MessageKindExecute))
	buf.AppendInt32(int32(length))
	buf.AppendString(x.PortalName)
	buf.AppendInt32(x.RowLimit)
	return buf.Bytes(), nil
}

func (x *MsgExecute) UnmarshalBinary(b []byte) error {
	b, err := shiftHeader(MessageKindExecute, b)
	if err != nil {
		return invalidFormat(err)
	}

	buf := pgio.NewBuffer(b)

	portal, err := buf.ShiftString()
	if err != nil {
		return invalidFormat(err)
	}

	limit, err := buf.ShiftInt32()
	if err != nil {
		return invalidFormat(err)
	}

	x.PortalName = portal
	x.RowLimit = limit
	return nil
}

var _ Message = &MsgFlush{}
var _ Frontend = &MsgFlush{}

type MsgFlush struct{}

func (x *MsgFlush) message() {}

func (x *MsgFlush) frontend() {}

func (x *MsgFlush) AppendBinary(b []byte) ([]byte, error) {
	const length = sizeMessageLength
	const size = sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(byte(MessageKindFlush))
	buf.AppendInt32(int32(length))
	return buf.Bytes(), nil
}

func (x *MsgFlush) UnmarshalBinary(b []byte) error {
	b, err := shiftHeader(MessageKindFlush, b)
	if err != nil {
		return invalidFormat(err)
	}

	if len(b) > 0 {
		return invalidFormat(pgio.ErrValueOverflow)
	}
	return nil
}

var _ Message = &MsgFunctionCall{}
var _ Frontend = &MsgFunctionCall{}

type MsgFunctionCall struct {
	ObjectID int32

	// ArgumentFormats may have zero elements, indicating that there are no
	// arguments, or that all arguments use the default format (text); or one,
	// in which case the specified format code is applied to all arguments; or
	// its element count may equal the total number of arguments.
	ArgumentFormats []FormatKind

	ArgumentValues [][]byte
	ResultFormat   FormatKind
}

func (x *MsgFunctionCall) message() {}

func (x *MsgFunctionCall) frontend() {}

func (x *MsgFunctionCall) AppendBinary(b []byte) ([]byte, error) {
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
	buf.AppendByte(byte(MessageKindFunctionCall))
	buf.AppendInt32(int32(length))
	buf.AppendInt32(x.ObjectID)
	buf.AppendInt16(int16(countFormats))

	for _, format := range x.ArgumentFormats {
		buf.AppendInt16(int16(format))
	}
	buf.AppendInt16(int16(countArguments))

	for i := range countArguments {
		value := x.ArgumentValues[i]
		length := len(value)
		buf.AppendInt32(int32(length))
		buf.AppendByte(value...)
	}
	buf.AppendInt16(int16(x.ResultFormat))
	return buf.Bytes(), nil
}

func (x *MsgFunctionCall) UnmarshalBinary(b []byte) error {
	b, err := shiftHeader(MessageKindFunctionCall, b)
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

	formats := make([]FormatKind, 0, countFormats)
	for range countFormats {
		format, err := buf.ShiftInt16()
		if err != nil {
			return invalidFormat(err)
		}
		formats = append(formats, FormatKind(format))
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
	x.ResultFormat = FormatKind(resultFormat)
	return nil
}

var _ Message = &MsgGSSENCRequest{}
var _ Frontend = &MsgGSSENCRequest{}

const (
	encHigh               int32 = 1234
	encLow                int32 = 5680
	CodeEncryptionRequest int32 = encLow | encHigh<<16
)

type MsgGSSENCRequest struct{}

func (x *MsgGSSENCRequest) message() {}

func (x *MsgGSSENCRequest) frontend() {}

func (x *MsgGSSENCRequest) AppendBinary(b []byte) ([]byte, error) {
	const sizeCode = 4
	const length = sizeMessageLength + sizeCode

	buf := pgio.NewBuffer(b)
	buf.Grow(length)
	buf.AppendInt32(length)
	buf.AppendInt32(CodeEncryptionRequest)
	return buf.Bytes(), nil
}

func (x *MsgGSSENCRequest) UnmarshalBinary(b []byte) error {
	b, err := shiftLength(b)
	if err != nil {
		return invalidFormat(err)
	}

	code, b, err := pgio.ShiftInt32(b)
	if err != nil {
		return invalidFormat(err)
	}

	if code != CodeEncryptionRequest {
		return invalidFormat(pgio.ErrUnknownCode)
	}

	if len(b) > 0 {
		return invalidFormat(pgio.ErrValueOverflow)
	}
	return nil
}

var _ Message = &MsgGSSResponse{}
var _ Frontend = &MsgGSSResponse{}

type MsgGSSResponse struct {
	Data []byte
}

func (x *MsgGSSResponse) message() {}

func (x *MsgGSSResponse) frontend() {}

func (x *MsgGSSResponse) AppendBinary(b []byte) ([]byte, error) {
	length := sizeMessageLength + len(x.Data)

	if length > math.MaxInt32 {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}
	size := sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(byte(MessageKindGSSResponse))
	buf.AppendInt32(int32(length))
	buf.AppendByte(x.Data...)
	return buf.Bytes(), nil
}

func (x *MsgGSSResponse) UnmarshalBinary(b []byte) error {
	b, err := shiftHeader(MessageKindGSSResponse, b)
	if err != nil {
		return invalidFormat(err)
	}

	x.Data = make([]byte, len(b))
	copy(x.Data, b)
	return nil
}

var _ Message = &MsgParse{}
var _ Frontend = &MsgParse{}

type MsgParse struct {
	ParameterDataTypes       []int32
	DestinationStatementName string
	Query                    string
}

func (x *MsgParse) message() {}

func (x *MsgParse) frontend() {}

func (x *MsgParse) AppendBinary(b []byte) ([]byte, error) {
	const sizeParameterDataType = 4
	const sizeParameterDataTypeCount = 2

	sizeDestinationStatementName := len(x.DestinationStatementName) + 1 // null terminated string
	sizeQuery := len(x.Query) + 1                                       // null terminated string

	countParameterDataTypes := len(x.ParameterDataTypes)

	if countParameterDataTypes > math.MaxInt16 {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	length := sizeMessageLength +
		sizeDestinationStatementName +
		sizeQuery +
		sizeParameterDataTypeCount +
		countParameterDataTypes*sizeParameterDataType

	if length > math.MaxInt32 {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	buf := pgio.NewBuffer(b)

	buf.Grow(size)
	buf.AppendByte(byte(MessageKindParse))
	buf.AppendInt32(int32(length))
	buf.AppendString(x.DestinationStatementName)
	buf.AppendString(x.Query)
	buf.AppendInt16(int16(countParameterDataTypes))

	for i := range countParameterDataTypes {
		buf.AppendInt32(x.ParameterDataTypes[i])
	}
	return buf.Bytes(), nil
}

func (x *MsgParse) UnmarshalBinary(b []byte) error {
	b, err := shiftHeader(MessageKindParse, b)
	if err != nil {
		return invalidFormat(err)
	}

	buf := pgio.NewBuffer(b)

	destinationStatementName, err := buf.ShiftString()
	if err != nil {
		return invalidFormat(err)
	}

	query, err := buf.ShiftString()
	if err != nil {
		return invalidFormat(err)
	}

	countParameterDataTypes, err := buf.ShiftInt16()
	if err != nil {
		return invalidFormat(err)
	}

	parameterDataTypes := make([]int32, 0, countParameterDataTypes)

	for range countParameterDataTypes {
		parameterDataType, err := buf.ShiftInt32()
		if err != nil {
			return invalidFormat(err)
		}
		parameterDataTypes = append(parameterDataTypes, parameterDataType)
	}

	x.DestinationStatementName = destinationStatementName
	x.Query = query
	x.ParameterDataTypes = parameterDataTypes
	return nil
}

var _ Message = &MsgPasswordMessage{}
var _ Frontend = &MsgPasswordMessage{}

type MsgPasswordMessage struct {
	Password string
}

func (x *MsgPasswordMessage) message() {}

func (x *MsgPasswordMessage) frontend() {}

func (x *MsgPasswordMessage) AppendBinary(b []byte) ([]byte, error) {
	sizePassword := len(x.Password) + 1 // null terminated string

	length := sizeMessageLength + sizePassword

	if length > math.MaxInt32 {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	buf := pgio.NewBuffer(b)

	buf.Grow(size)
	buf.AppendByte(byte(MessageKindPasswordMessage))
	buf.AppendInt32(int32(length))
	buf.AppendString(x.Password)
	return buf.Bytes(), nil
}

func (x *MsgPasswordMessage) UnmarshalBinary(b []byte) error {
	b, err := shiftHeader(MessageKindPasswordMessage, b)
	if err != nil {
		return invalidFormat(err)
	}

	password, b, err := pgio.ShiftString(b)
	if err != nil {
		return invalidFormat(err)
	}

	if len(b) > 0 {
		return invalidFormat(pgio.ErrValueOverflow)
	}

	x.Password = password
	return nil
}

var _ Message = &MsgQuery{}
var _ Frontend = &MsgQuery{}

type MsgQuery struct {
	Value string
}

func (x *MsgQuery) message() {}

func (x *MsgQuery) frontend() {}

func (x *MsgQuery) AppendBinary(b []byte) ([]byte, error) {
	sizeQuery := len(x.Value)

	length := sizeMessageLength + sizeQuery

	size := sizeMessageKind + length

	buf := pgio.NewBuffer(b)

	buf.Grow(size)
	buf.AppendByte(byte(MessageKindQuery))
	buf.AppendInt32(int32(length))
	buf.AppendString(x.Value)
	return buf.Bytes(), nil
}

func (x *MsgQuery) UnmarshalBinary(b []byte) error {
	b, err := shiftHeader(MessageKindQuery, b)
	if err != nil {
		return invalidFormat(err)
	}

	query, b, err := pgio.ShiftString(b)
	if err != nil {
		return invalidFormat(err)
	}

	if len(b) > 0 {
		return invalidFormat(pgio.ErrValueOverflow)
	}

	x.Value = query
	return nil
}

var _ Message = &MsgSASLInitialResponse{}
var _ Frontend = &MsgSASLInitialResponse{}

type MsgSASLInitialResponse struct {
	Name     string
	Response []byte // will be nil when there is no initial response.
}

func (x *MsgSASLInitialResponse) message() {}

func (x *MsgSASLInitialResponse) frontend() {}

func (x *MsgSASLInitialResponse) AppendBinary(b []byte) ([]byte, error) {
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
	buf.AppendByte(byte(MessageKindSASLInitialResponse))
	buf.AppendInt32(int32(length))
	buf.AppendString(x.Name)
	buf.AppendInt32(int32(sizeResponse))
	buf.AppendByte(x.Response...)
	return buf.Bytes(), nil
}

func (x *MsgSASLInitialResponse) UnmarshalBinary(b []byte) error {
	b, err := shiftHeader(MessageKindSASLInitialResponse, b)
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

var _ Message = &MsgSASLResponse{}
var _ Frontend = &MsgSASLResponse{}

type MsgSASLResponse struct {
	Data []byte
}

func (x *MsgSASLResponse) message() {}

func (x *MsgSASLResponse) frontend() {}

func (x *MsgSASLResponse) AppendBinary(b []byte) ([]byte, error) {
	sizeData := len(x.Data)

	length := sizeMessageLength + sizeData

	if length > math.MaxInt32 {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	buf := pgio.NewBuffer(b)

	buf.Grow(size)
	buf.AppendByte(byte(MessageKindSASLResponse))
	buf.AppendInt32(int32(length))
	buf.AppendByte(x.Data...)
	return buf.Bytes(), nil
}

func (x *MsgSASLResponse) UnmarshalBinary(b []byte) error {
	b, err := shiftHeader(MessageKindSASLResponse, b)
	if err != nil {
		return invalidFormat(err)
	}

	x.Data = make([]byte, len(b))
	copy(x.Data, b)
	return nil
}

var _ Message = &MsgSSLRequest{}
var _ Frontend = &MsgSSLRequest{}

type MsgSSLRequest struct{}

func (x *MsgSSLRequest) message() {}

func (x *MsgSSLRequest) frontend() {}

func (x *MsgSSLRequest) AppendBinary(b []byte) ([]byte, error) {
	const sizeCode = 4

	length := sizeMessageLength + sizeCode

	buf := pgio.NewBuffer(b)

	buf.Grow(length)
	buf.AppendInt32(int32(length))
	buf.AppendInt32(CodeSSLRequest)
	return buf.Bytes(), nil
}

func (x *MsgSSLRequest) UnmarshalBinary(b []byte) error {
	b, err := shiftLength(b)
	if err != nil {
		return invalidFormat(err)
	}

	code, b, err := pgio.ShiftInt32(b)
	if err != nil {
		return invalidFormat(err)
	}

	if code != CodeSSLRequest {
		return invalidFormat(pgio.ErrUnknownCode)
	}

	if len(b) > 0 {
		return invalidFormat(pgio.ErrValueOverflow)
	}
	return nil
}

type ProtocolVersion int32

func (x ProtocolVersion) Major() int32 {
	return int32(x) >> 16
}

func (x ProtocolVersion) Minor() int32 {
	return int32(x) & 0xFF
}

var _ Message = &MsgStartupMessage{}
var _ Frontend = &MsgStartupMessage{}

type MsgStartupMessage struct {
	ProtocolVersion ProtocolVersion
	Parameters      map[string]string
}

func (x *MsgStartupMessage) message() {}

func (x *MsgStartupMessage) frontend() {}

func (x *MsgStartupMessage) AppendBinary(b []byte) ([]byte, error) {
	const sizeProtocolVersion = 4

	var sizeParameters int

	for key, value := range x.Parameters {
		sizeParameters += (len(key) + 1)   // null terminated string
		sizeParameters += (len(value) + 1) // null terminated string
	}
	sizeParameters += 1 // null terminated list

	length := sizeMessageLength +
		sizeProtocolVersion +
		sizeParameters

	if length > math.MaxInt32 {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	buf := pgio.NewBuffer(b)

	buf.Grow(length)
	buf.AppendInt32(int32(length))
	buf.AppendInt32(int32(x.ProtocolVersion))

	for key, value := range x.Parameters {
		buf.AppendString(key)
		buf.AppendString(value)
	}
	buf.AppendByte(0)
	return buf.Bytes(), nil
}

func (x *MsgStartupMessage) UnmarshalBinary(b []byte) error {
	b, err := shiftLength(b)
	if err != nil {
		return invalidFormat(err)
	}

	buf := pgio.NewBuffer(b)

	protocolVersion, err := buf.ShiftInt32()
	if err != nil {
		return invalidFormat(err)
	}

	parameters := make(map[string]string)

	key, err := buf.ShiftString()
	if err != nil {
		return invalidFormat(err)
	}

	for len(key) > 0 {
		value, err := buf.ShiftString()
		if err != nil {
			return invalidFormat(err)
		}
		parameters[key] = value

		key, err = buf.ShiftString()
		if err != nil {
			return invalidFormat(err)
		}
	}

	x.ProtocolVersion = ProtocolVersion(protocolVersion)
	x.Parameters = parameters
	return nil
}

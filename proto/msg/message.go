package msg

import (
	"bytes"
	"encoding"
	"errors"
	"fmt"
	"gopsql/internal/bx"
	"io"
	"math"
	"slices"
)

const (
	KindAuthentication           byte = 'R'
	KindBackendKeyData           byte = 'K'
	KindBind                     byte = 'B'
	KindBindComplete             byte = '2'
	KindClose                    byte = 'C'
	KindCloseComplete            byte = '3'
	KindCommandComplete          byte = 'C'
	KindCopyData                 byte = 'd'
	KindCopyDone                 byte = 'c'
	KindCopyFail                 byte = 'f'
	KindCopyInResponse           byte = 'G'
	KindCopyOutResponse          byte = 'H'
	KindCopyBothResponse         byte = 'W'
	KindDataRow                  byte = 'D'
	KindDescribe                 byte = 'D'
	KindEmptyQueryResponse       byte = 'I'
	KindErrorResponse            byte = 'E'
	KindExecute                  byte = 'E'
	KindFlush                    byte = 'H'
	KindFunctionCall             byte = 'F'
	KindFunctionCallResponse     byte = 'V'
	KindGSSResponse              byte = 'p'
	KindNegotiateProtocolVersion byte = 'v'
	KindNoData                   byte = 'n'
	KindNoticeResponse           byte = 'N'
	KindNotificationResponse     byte = 'A'
	KindParameterDescription     byte = 't'
	KindParameterStatus          byte = 'S'
	KindParseComplete            byte = '1'
	KindPortalSuspended          byte = 's'
	KindReadyForQuery            byte = 'Z'
	KindRowDescription           byte = 'T'
)

const (
	KindAuthGSS          int32 = 7
	KindAuthGSSContinue  int32 = 8
	KindAuthSSPI         int32 = 9
	KindAuthSASL         int32 = 10
	KindAuthSASLContinue int32 = 11
	KindAuthSASLFinal    int32 = 12
)

const (
	FieldSeverity         byte = 'S'
	FieldSeverityRaw      byte = 'V'
	FieldCode             byte = 'C'
	FieldMessage          byte = 'M'
	FieldDetail           byte = 'D'
	FieldHint             byte = 'H'
	FieldPosition         byte = 'P'
	FieldInternalPosition byte = 'p'
	FieldInternalQuery    byte = 'q'
	FieldWhere            byte = 'W'
	FieldSchema           byte = 's'
	FieldTable            byte = 't'
	FieldColumn           byte = 'c'
	FieldDataType         byte = 'd'
	FieldConstraint       byte = 'n'
	FieldFile             byte = 'F'
	FieldLine             byte = 'L'
	FieldRoutine          byte = 'R'
)

const (
	FormatText   int8 = 0
	FormatBinary int8 = 1
)

const (
	ColumnFormatText   int16 = 0
	ColumnFormatBinary int16 = 1
)

const (
	TxStatusIdle   byte = 'I'
	TxStatusActive byte = 'T'
	TxStatusError  byte = 'E'
)

const (
	sizeMessageKind   = 1
	sizeMessageLength = 4
	sizeAuthKind      = 4
)

var (
	NullByte = []byte{0}
)

var (
	ErrInvalidFormat  = errors.New("invalid format")
	ErrUnexpectedKind = errors.New("unexpected kind")
)

func invalidFormat(cause error) error {
	return fmt.Errorf("%w: %w", ErrInvalidFormat, cause)
}

func unexpectedKind(got, want byte) error {
	return fmt.Errorf("%w: got '%d', want '%d'", ErrUnexpectedKind, got, want)
}

func unexpectedAuthKind(got, want int32) error {
	return fmt.Errorf("%w: got '%d', want '%d'", ErrUnexpectedKind, got, want)
}

func ShiftLength(b []byte) ([]byte, error) {
	length, b, err := bx.ShiftInt32(b)
	if err != nil {
		return nil, err
	}

	size := int(length) - 4

	if size > len(b) {
		return nil, bx.ErrValueUnderflow
	}
	return b[:size], nil
}

func ShiftHeader(b []byte) (byte, []byte, error) {
	msgKind, b, err := bx.ShiftByte(b)
	if err != nil {
		return 0, nil, err
	}
	b, err = ShiftLength(b)
	return msgKind, b, err
}

type Message interface {
	encoding.BinaryAppender
	encoding.BinaryUnmarshaler

	message()
}

type msg struct{}

func (x msg) message() {}

type Backend interface {
	Message

	backend()
}

type back struct{}

func (x back) backend() {}

type Frontend interface {
	Message

	frontend()
}

type front struct{}

func (x front) frontend() {}

var _ Message = &AuthGSS{}
var _ Backend = &AuthGSS{}

type AuthGSS struct {
	msg
	back
}

func (x *AuthGSS) AppendBinary(b []byte) ([]byte, error) {
	const length = sizeMessageLength + sizeAuthKind
	const size = sizeMessageKind + length

	b = slices.Grow(b, size)
	b = bx.AppendByte(b, KindAuthentication)
	b = bx.AppendInt32(b, int32(length))
	b = bx.AppendInt32(b, KindAuthGSS)
	return b, nil
}

func (x *AuthGSS) UnmarshalBinary(b []byte) error {
	msgKind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if msgKind != KindAuthentication {
		return unexpectedKind(msgKind, KindAuthentication)
	}

	authKind, b, err := bx.ShiftInt32(b)
	if err != nil {
		return invalidFormat(err)
	}

	if authKind != KindAuthGSS {
		return unexpectedAuthKind(authKind, KindAuthGSS)
	}
	if len(b) > 0 {
		return invalidFormat(bx.ErrValueOverflow)
	}
	return nil
}

var _ Message = &AuthGSSContinue{}
var _ Backend = &AuthGSSContinue{}

type AuthGSSContinue struct {
	msg
	back

	Data []byte
}

func (x *AuthGSSContinue) AppendBinary(b []byte) ([]byte, error) {
	sizeData := len(x.Data)
	length := sizeMessageLength + sizeAuthKind + sizeData
	size := sizeMessageKind + length

	b = slices.Grow(b, size)
	b = bx.AppendByte(b, KindAuthentication)
	b = bx.AppendInt32(b, int32(length))
	b = bx.AppendInt32(b, KindAuthGSSContinue)
	b = bx.AppendByte(b, x.Data...)
	return b, nil
}

func (x *AuthGSSContinue) UnmarshalBinary(b []byte) error {
	msgKind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if msgKind != KindAuthentication {
		return unexpectedKind(msgKind, KindAuthentication)
	}

	authKind, b, err := bx.ShiftInt32(b)
	if err != nil {
		return invalidFormat(err)
	}

	if authKind != KindAuthGSSContinue {
		return unexpectedAuthKind(authKind, KindAuthGSSContinue)
	}
	x.Data = make([]byte, len(b))
	copy(x.Data, b)
	return nil
}

var _ Message = &AuthSSPI{}
var _ Backend = &AuthSSPI{}

type AuthSSPI struct {
	msg
	back
}

func (x *AuthSSPI) AppendBinary(b []byte) ([]byte, error) {
	const length = sizeMessageLength + sizeAuthKind
	const size = sizeMessageKind + length

	b = slices.Grow(b, size)
	b = bx.AppendByte(b, KindAuthentication)
	b = bx.AppendInt32(b, int32(length))
	b = bx.AppendInt32(b, KindAuthSSPI)
	return b, nil
}

func (x *AuthSSPI) UnmarshalBinary(b []byte) error {
	msgKind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if msgKind != KindAuthentication {
		return unexpectedKind(msgKind, KindAuthentication)
	}

	authKind, b, err := bx.ShiftInt32(b)
	if err != nil {
		return invalidFormat(err)
	}

	if authKind != KindAuthSSPI {
		return unexpectedAuthKind(authKind, KindAuthSSPI)
	}

	if len(b) > 0 {
		return invalidFormat(bx.ErrValueOverflow)
	}
	return nil
}

var _ Message = &AuthSASL{}
var _ Backend = &AuthSASL{}

type AuthSASL struct {
	msg
	back

	Mechanisms []string
}

func (x *AuthSASL) AppendBinary(b []byte) ([]byte, error) {
	countMechanisms := len(x.Mechanisms)
	sizeMechanisms := 0

	for i := range countMechanisms {
		sizeMechanisms += len(x.Mechanisms[i]) + 1 // null terminated string
	}
	sizeMechanisms += 1 // null terminated list

	length := sizeMessageLength + sizeAuthKind + sizeMechanisms

	if length > math.MaxInt32 {
		return nil, invalidFormat(bx.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	b = slices.Grow(b, size)
	b = bx.AppendByte(b, KindAuthentication)
	b = bx.AppendInt32(b, int32(length))
	b = bx.AppendInt32(b, KindAuthSASL)
	b = bx.AppendString(b, x.Mechanisms...)
	b = bx.AppendByte(b, 0x0)
	return b, nil
}

func (x *AuthSASL) UnmarshalBinary(b []byte) error {
	msgKind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if msgKind != KindAuthentication {
		return unexpectedKind(msgKind, KindAuthentication)
	}

	authKind, b, err := bx.ShiftInt32(b)
	if err != nil {
		return invalidFormat(err)
	}

	if authKind != KindAuthSASL {
		return unexpectedAuthKind(authKind, KindAuthSASL)
	}
	x.Mechanisms = make([]string, 0, bytes.Count(b, NullByte))

	for {
		var mechanism string
		var err error

		mechanism, b, err = bx.ShiftString(b)
		if err != nil {
			return invalidFormat(err)
		}

		if len(mechanism) == 0 {
			break
		}
		x.Mechanisms = append(x.Mechanisms, mechanism)
	}
	return nil
}

var _ Message = &AuthSASLContinue{}
var _ Backend = &AuthSASLContinue{}

type AuthSASLContinue struct {
	msg
	back

	Data []byte
}

func (x *AuthSASLContinue) AppendBinary(b []byte) ([]byte, error) {
	sizeData := len(x.Data)

	length := sizeMessageLength + sizeAuthKind + sizeData

	if length > math.MaxInt32 {
		return nil, invalidFormat(bx.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	b = slices.Grow(b, size)
	b = bx.AppendByte(b, KindAuthentication)
	b = bx.AppendInt32(b, int32(length))
	b = bx.AppendInt32(b, KindAuthSASLContinue)
	b = bx.AppendByte(b, x.Data...)
	return b, nil
}

func (x *AuthSASLContinue) UnmarshalBinary(b []byte) error {
	msgKind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if msgKind != KindAuthentication {
		return unexpectedKind(msgKind, KindAuthentication)
	}

	authKind, b, err := bx.ShiftInt32(b)
	if err != nil {
		return invalidFormat(err)
	}

	if authKind != KindAuthSASLContinue {
		return unexpectedAuthKind(authKind, KindAuthSASLContinue)
	}
	x.Data = make([]byte, len(b))
	copy(x.Data, b)
	return nil
}

var _ Message = &AuthSASLFinal{}
var _ Backend = &AuthSASLFinal{}

type AuthSASLFinal struct {
	msg
	back

	Data []byte
}

func (x *AuthSASLFinal) AppendBinary(b []byte) ([]byte, error) {
	sizeData := len(x.Data)

	length := sizeMessageLength + sizeAuthKind + sizeData

	if length > math.MaxInt32 {
		return nil, invalidFormat(bx.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	b = slices.Grow(b, size)
	b = bx.AppendByte(b, KindAuthentication)
	b = bx.AppendInt32(b, int32(length))
	b = bx.AppendInt32(b, KindAuthSASLFinal)
	b = bx.AppendByte(b, x.Data...)
	return b, nil
}

func (x *AuthSASLFinal) UnmarshalBinary(b []byte) error {
	msgKind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if msgKind != KindAuthentication {
		return unexpectedKind(msgKind, KindAuthentication)
	}

	authKind, b, err := bx.ShiftInt32(b)
	if err != nil {
		return invalidFormat(err)
	}

	if authKind != KindAuthSASLFinal {
		return unexpectedAuthKind(authKind, KindAuthSASLFinal)
	}
	x.Data = make([]byte, len(b))
	copy(x.Data, b)
	return nil
}

var _ Message = &BackendKeyData{}
var _ Backend = &BackendKeyData{}

type BackendKeyData struct {
	msg
	back

	ProcessID int32
	SecretKey []byte
}

func (x *BackendKeyData) AppendBinary(b []byte) ([]byte, error) {
	const sizeProcessID = 4
	sizeSecretKey := len(x.SecretKey)

	if sizeSecretKey < 4 {
		return nil, invalidFormat(bx.ErrValueUnderflow)
	}

	if sizeSecretKey > 256 {
		return nil, invalidFormat(bx.ErrValueOverflow)
	}

	length := sizeMessageLength + sizeProcessID + sizeSecretKey

	if length > math.MaxInt32 {
		return nil, invalidFormat(bx.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	b = slices.Grow(b, size)
	b = bx.AppendByte(b, KindBackendKeyData)
	b = bx.AppendInt32(b, int32(length))
	b = bx.AppendInt32(b, x.ProcessID)
	b = bx.AppendByte(b, x.SecretKey...)
	return b, nil
}

func (x *BackendKeyData) UnmarshalBinary(b []byte) error {
	kind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if kind != KindBackendKeyData {
		return unexpectedKind(kind, KindBackendKeyData)
	}

	x.ProcessID, b, err = bx.ShiftInt32(b)
	if err != nil {
		return invalidFormat(err)
	}

	if len(b) < 4 {
		return invalidFormat(bx.ErrValueUnderflow)
	}

	if len(b) > 256 {
		return invalidFormat(bx.ErrValueOverflow)
	}
	x.SecretKey = make([]byte, len(b))
	copy(x.SecretKey, b)
	return nil
}

var _ Message = &Bind{}
var _ Frontend = &Bind{}

type Bind struct {
	msg
	front

	DestinationName      string
	SourceName           string
	ParameterFormatCodes []int16
	ParameterData        [][]byte
	ColumnFormatCodes    []int16
}

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
		return nil, invalidFormat(bx.ErrValueOverflow)
	}

	sizeParamFmtCodes := paramFmtCodeCount * sizeParamFmtCode

	paramDataCount := len(x.ParameterData)
	if paramDataCount > math.MaxInt16 {
		return nil, invalidFormat(bx.ErrValueOverflow)
	}

	sizeParamData := 0

	for i := range paramDataCount {
		length := len(x.ParameterData[i])
		if length > math.MaxInt32 {
			return nil, invalidFormat(bx.ErrValueOverflow)
		}
		sizeParamData += sizeParamDatum + length // size prefixed
	}

	colFmtCodeCount := len(x.ColumnFormatCodes)
	if colFmtCodeCount > math.MaxInt16 {
		return nil, invalidFormat(bx.ErrValueOverflow)
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
		return nil, invalidFormat(bx.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	b = slices.Grow(b, size)
	b = bx.AppendByte(b, KindBind)
	b = bx.AppendInt32(b, int32(length))
	b = bx.AppendString(b, x.DestinationName)
	b = bx.AppendString(b, x.SourceName)
	b = bx.AppendInt16(b, int16(paramFmtCodeCount))
	b = bx.AppendInt16(b, x.ParameterFormatCodes...)
	b = bx.AppendInt16(b, int16(paramDataCount))

	for i := range paramDataCount {
		sizeData := len(x.ParameterData[i])
		b = bx.AppendInt32(b, int32(sizeData))
		b = bx.AppendByte(b, x.ParameterData[i]...)
	}

	b = bx.AppendInt16(b, int16(colFmtCodeCount))
	b = bx.AppendInt16(b, x.ColumnFormatCodes...)
	return b, nil
}

func (x *Bind) UnmarshalBinary(b []byte) error {
	destination, b, err := bx.ShiftString(b)
	if err != nil {
		return invalidFormat(err)
	}
	x.DestinationName = destination

	source, b, err := bx.ShiftString(b)
	if err != nil {
		return invalidFormat(err)
	}
	x.SourceName = source

	paramFmtCodeCount, b, err := bx.ShiftInt16(b)
	if err != nil {
		return invalidFormat(err)
	}
	x.ParameterFormatCodes = make([]int16, paramFmtCodeCount)

	for i := range paramFmtCodeCount {
		var code int16
		code, b, err = bx.ShiftInt16(b)
		if err != nil {
			return invalidFormat(err)
		}
		x.ParameterFormatCodes[i] = code
	}

	paramDataCount, b, err := bx.ShiftInt16(b)
	if err != nil {
		return invalidFormat(err)
	}
	x.ParameterData = make([][]byte, paramDataCount)

	for i := range paramDataCount {
		var dataLen int32
		dataLen, b, err = bx.ShiftInt32(b)
		if err != nil {
			return invalidFormat(err)
		}

		var data []byte
		data, b, err = bx.ShiftBytes(b, int(dataLen))
		if err != nil {
			return invalidFormat(err)
		}
		x.ParameterData[i] = data
	}

	colFmtCodeCount, b, err := bx.ShiftInt16(b)
	if err != nil {
		return invalidFormat(err)
	}
	x.ColumnFormatCodes = make([]int16, colFmtCodeCount)

	for i := range colFmtCodeCount {
		var data int16
		data, b, err = bx.ShiftInt16(b)
		if err != nil {
			return invalidFormat(err)
		}
		x.ColumnFormatCodes[i] = data
	}
	return nil
}

var _ Message = &BindComplete{}
var _ Backend = &BindComplete{}

type BindComplete struct {
	msg
	back
}

func (x *BindComplete) AppendBinary(b []byte) ([]byte, error) {
	const length = sizeMessageLength
	const size = sizeMessageKind + length

	b = slices.Grow(b, size)
	b = bx.AppendByte(b, KindBindComplete)
	b = bx.AppendInt32(b, int32(length))
	return b, nil
}

func (x *BindComplete) UnmarshalBinary(b []byte) error {
	kind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if kind != KindBindComplete {
		return unexpectedKind(kind, KindBindComplete)
	}

	if len(b) > 0 {
		return invalidFormat(bx.ErrValueOverflow)
	}
	return nil
}

var _ Message = &CancelRequest{}
var _ Frontend = &CancelRequest{}

const (
	cancelHigh        int32 = 1234
	cancelLow         int32 = 5678
	CodeCancelRequest int32 = cancelLow | cancelHigh<<16
)

type CancelRequest struct {
	msg
	front

	ProcessID int32
	SecretKey []byte
}

func (x *CancelRequest) AppendBinary(b []byte) ([]byte, error) {
	const sizeCode = 4
	const sizeProcessID = 4

	sizeSecretKey := len(x.SecretKey)

	if sizeSecretKey > 256 {
		return nil, invalidFormat(bx.ErrValueOverflow)
	}

	if sizeSecretKey < 4 {
		return nil, invalidFormat(bx.ErrValueUnderflow)
	}

	length := sizeMessageLength +
		sizeCode +
		sizeProcessID +
		sizeSecretKey

	b = slices.Grow(b, length)
	b = bx.AppendInt32(b, int32(length))
	b = bx.AppendInt32(b, CodeCancelRequest)
	b = bx.AppendInt32(b, x.ProcessID)
	b = bx.AppendByte(b, x.SecretKey...)
	return b, nil
}

func (x *CancelRequest) UnmarshalBinary(b []byte) error {
	b, err := ShiftLength(b)
	if err != nil {
		return invalidFormat(err)
	}
	processID, b, err := bx.ShiftInt32(b)
	if err != nil {
		return err
	}
	x.ProcessID = processID
	x.SecretKey = make([]byte, len(b))
	copy(x.SecretKey, b)
	return nil
}

var _ Message = &Close{}
var _ Frontend = &Close{}

type Close struct {
	msg
	front

	Kind byte
	Name string
}

func (x *Close) AppendBinary(b []byte) ([]byte, error) {
	const sizeKind = 1

	sizeName := len(x.Name) + 1 // null terminated string

	length := sizeMessageLength + sizeKind + sizeName

	if length > math.MaxInt32 {
		return nil, invalidFormat(bx.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	b = slices.Grow(b, size)
	b = bx.AppendByte(b, KindClose)
	b = bx.AppendInt32(b, int32(length))
	b = bx.AppendByte(b, x.Kind)
	b = bx.AppendString(b, x.Name)
	return b, nil
}

func (x *Close) UnmarshalBinary(b []byte) error {
	msgKind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if msgKind != KindClose {
		return unexpectedKind(msgKind, KindClose)
	}

	kind, b, err := bx.ShiftByte(b)
	if err != nil {
		return invalidFormat(err)
	}

	name, b, err := bx.ShiftString(b)
	if err != nil {
		return invalidFormat(err)
	}
	x.Kind = kind
	x.Name = name
	return nil
}

var _ Message = &CloseComplete{}
var _ Backend = &CloseComplete{}

type CloseComplete struct {
	msg
	back
}

func (x *CloseComplete) AppendBinary(b []byte) ([]byte, error) {
	const length = sizeMessageLength
	const size = sizeMessageKind + length

	b = slices.Grow(b, size)
	b = bx.AppendByte(b, KindCloseComplete)
	b = bx.AppendInt32(b, int32(length))
	return b, nil
}

func (x *CloseComplete) UnmarshalBinary(b []byte) error {
	kind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if kind != KindCloseComplete {
		return unexpectedKind(kind, KindCloseComplete)
	}

	if len(b) > 0 {
		return invalidFormat(bx.ErrValueOverflow)
	}
	return nil
}

var _ Message = &CommandComplete{}
var _ Backend = &CommandComplete{}

type CommandComplete struct {
	msg
	back

	Tag string
}

func (x *CommandComplete) AppendBinary(b []byte) ([]byte, error) {
	sizeTag := len(x.Tag) + 1 // null terminated string
	length := sizeMessageLength + sizeTag

	if length > math.MaxInt32 {
		return nil, invalidFormat(bx.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	b = slices.Grow(b, size)
	b = bx.AppendByte(b, KindCommandComplete)
	b = bx.AppendInt32(b, int32(length))
	b = bx.AppendString(b, x.Tag)
	return b, nil
}

func (x *CommandComplete) UnmarshalBinary(b []byte) error {
	kind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if kind != KindCommandComplete {
		return unexpectedKind(kind, KindCommandComplete)
	}

	tag, b, err := bx.ShiftString(b)
	if err != nil {
		return invalidFormat(err)
	}
	x.Tag = tag
	return nil
}

var _ Message = &CopyData{}
var _ Frontend = &CopyData{}
var _ Backend = &CopyData{}

type CopyData struct {
	msg
	front
	back

	Data []byte
}

func (x *CopyData) AppendBinary(b []byte) ([]byte, error) {
	sizeData := len(x.Data)
	length := sizeMessageLength + sizeData

	if length > math.MaxInt32 {
		return nil, invalidFormat(bx.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	b = slices.Grow(b, size)
	b = bx.AppendByte(b, KindCopyData)
	b = bx.AppendInt32(b, int32(length))
	b = bx.AppendByte(b, x.Data...)
	return b, nil
}

func (x *CopyData) UnmarshalBinary(b []byte) error {
	kind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if kind != KindCopyData {
		return unexpectedKind(kind, KindCopyData)
	}

	x.Data = make([]byte, len(b))
	copy(x.Data, b)
	return nil
}

var _ Message = &CopyDone{}
var _ Frontend = &CopyDone{}
var _ Backend = &CopyDone{}

type CopyDone struct {
	msg
	front
	back
}

func (x *CopyDone) AppendBinary(b []byte) ([]byte, error) {
	const length = sizeMessageLength
	const size = sizeMessageKind + length

	b = slices.Grow(b, size)
	b = bx.AppendByte(b, KindCopyDone)
	b = bx.AppendInt32(b, int32(length))
	return b, nil
}

func (x *CopyDone) UnmarshalBinary(b []byte) error {
	kind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if kind != KindCopyDone {
		return unexpectedKind(kind, KindCopyDone)
	}

	if len(b) > 0 {
		return invalidFormat(bx.ErrValueOverflow)
	}
	return nil
}

var _ Message = &CopyFail{}
var _ Frontend = &CopyFail{}

type CopyFail struct {
	msg
	front

	Message string
}

func (x *CopyFail) AppendBinary(b []byte) ([]byte, error) {
	sizeMessage := len(x.Message) + 1 // null terminated string
	length := sizeMessageLength + sizeMessage

	if length > math.MaxInt32 {
		return nil, invalidFormat(bx.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	b = slices.Grow(b, size)
	b = bx.AppendByte(b, KindCopyFail)
	b = bx.AppendInt32(b, int32(length))
	b = bx.AppendString(b, x.Message)
	return b, nil
}

func (x *CopyFail) UnmarshalBinary(b []byte) error {
	kind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if kind != KindCopyFail {
		return unexpectedKind(kind, KindCopyFail)
	}

	m, b, err := bx.ShiftString(b)
	if err != nil {
		return invalidFormat(err)
	}
	x.Message = m
	return nil
}

var _ Message = &CopyInResponse{}
var _ Backend = &CopyInResponse{}

type CopyInResponse struct {
	msg
	back

	Format  int8
	Columns []int16
}

func (x *CopyInResponse) AppendBinary(b []byte) ([]byte, error) {
	const sizeFormat = 1
	const sizeColCount = 2
	const sizeCol = 2

	countCols := len(x.Columns)

	if countCols > math.MaxInt16 {
		return nil, invalidFormat(bx.ErrValueOverflow)
	}

	sizeCols := countCols * sizeCol

	length := sizeMessageLength +
		sizeFormat +
		sizeColCount +
		sizeCols

	if length > math.MaxInt32 {
		return nil, invalidFormat(bx.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	b = slices.Grow(b, size)
	b = bx.AppendByte(b, KindCopyInResponse)
	b = bx.AppendInt32(b, int32(length))
	b = bx.AppendInt8(b, x.Format)
	b = bx.AppendInt16(b, int16(countCols))
	b = bx.AppendInt16(b, x.Columns...)
	return b, nil
}

func (x *CopyInResponse) UnmarshalBinary(b []byte) error {
	kind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if kind != KindCopyInResponse {
		return unexpectedKind(kind, KindCopyInResponse)
	}

	format, b, err := bx.ShiftInt8(b)
	if err != nil {
		return invalidFormat(err)
	}

	length, b, err := bx.ShiftInt16(b)
	if err != nil {
		return invalidFormat(err)
	}

	columns := make([]int16, 0, length)

	for range length {
		var value int16
		value, b, err = bx.ShiftInt16(b)
		if err != nil {
			return invalidFormat(err)
		}
		columns = append(columns, value)
	}
	x.Format = format
	x.Columns = columns
	return nil
}

var _ Message = &CopyOutResponse{}
var _ Backend = &CopyOutResponse{}

type CopyOutResponse struct {
	msg
	back

	Format  int8
	Columns []int16
}

func (x *CopyOutResponse) AppendBinary(b []byte) ([]byte, error) {
	const sizeFormat = 1
	const sizeColCount = 2
	const sizeCol = 2

	countCols := len(x.Columns)

	if countCols > math.MaxInt16 {
		return nil, invalidFormat(bx.ErrValueOverflow)
	}

	sizeCols := countCols * sizeCol

	length := sizeMessageLength +
		sizeFormat +
		sizeColCount +
		sizeCols

	if length > math.MaxInt32 {
		return nil, invalidFormat(bx.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	b = slices.Grow(b, size)
	b = bx.AppendByte(b, KindCopyOutResponse)
	b = bx.AppendInt32(b, int32(length))
	b = bx.AppendInt8(b, x.Format)
	b = bx.AppendInt16(b, int16(countCols))
	b = bx.AppendInt16(b, x.Columns...)
	return b, nil
}

func (x *CopyOutResponse) UnmarshalBinary(b []byte) error {
	kind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if kind != KindCopyOutResponse {
		return unexpectedKind(kind, KindCopyOutResponse)
	}

	format, b, err := bx.ShiftInt8(b)
	if err != nil {
		return invalidFormat(err)
	}

	length, b, err := bx.ShiftInt16(b)
	if err != nil {
		return invalidFormat(err)
	}

	columns := make([]int16, 0, length)

	for range length {
		var value int16
		value, b, err = bx.ShiftInt16(b)
		if err != nil {
			return invalidFormat(err)
		}
		columns = append(columns, value)
	}
	x.Format = format
	x.Columns = columns
	return nil
}

var _ Message = &CopyBothResponse{}
var _ Backend = &CopyBothResponse{}

type CopyBothResponse struct {
	msg
	back

	Format  int8
	Columns []int16
}

func (x *CopyBothResponse) AppendBinary(b []byte) ([]byte, error) {
	const sizeFormat = 1
	const sizeColCount = 2
	const sizeCol = 2

	countCols := len(x.Columns)

	if countCols > math.MaxInt16 {
		return nil, invalidFormat(bx.ErrValueOverflow)
	}

	sizeCols := countCols * sizeCol

	length := sizeMessageLength +
		sizeFormat +
		sizeColCount +
		sizeCols

	if length > math.MaxInt32 {
		return nil, invalidFormat(bx.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	b = slices.Grow(b, size)
	b = bx.AppendByte(b, KindCopyBothResponse)
	b = bx.AppendInt32(b, int32(length))
	b = bx.AppendInt8(b, x.Format)
	b = bx.AppendInt16(b, int16(countCols))
	b = bx.AppendInt16(b, x.Columns...)
	return b, nil
}

func (x *CopyBothResponse) UnmarshalBinary(b []byte) error {
	kind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if kind != KindCopyBothResponse {
		return unexpectedKind(kind, KindCopyBothResponse)
	}

	format, b, err := bx.ShiftInt8(b)
	if err != nil {
		return invalidFormat(err)
	}

	length, b, err := bx.ShiftInt16(b)
	if err != nil {
		return invalidFormat(err)
	}

	columns := make([]int16, 0, length)

	for range length {
		var value int16
		value, b, err = bx.ShiftInt16(b)
		if err != nil {
			return invalidFormat(err)
		}
		columns = append(columns, value)
	}
	x.Format = format
	x.Columns = columns
	return nil
}

var _ Message = &DataRow{}
var _ Backend = &DataRow{}

type DataRow struct {
	msg
	back

	// First dimention is columns (can have 0 elements).
	// Second dimension is value data (can have 0 elements
	// or be nil).
	Columns [][]byte
}

func (x *DataRow) AppendBinary(b []byte) ([]byte, error) {
	const sizeColCount = 2
	const sizeColLength = 4

	countCols := len(x.Columns)

	if countCols > math.MaxInt16 {
		return nil, invalidFormat(bx.ErrValueOverflow)
	}

	sizeCols := 0

	for i := range countCols {
		lengthCol := len(x.Columns[i])

		if lengthCol > math.MaxInt32 {
			return nil, invalidFormat(bx.ErrValueOverflow)
		}
		sizeCols += sizeColLength + lengthCol
	}

	length := sizeMessageLength +
		sizeColCount +
		sizeCols

	if length > math.MaxInt32 {
		return nil, invalidFormat(bx.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	b = slices.Grow(b, size)
	b = bx.AppendByte(b, KindDataRow)
	b = bx.AppendInt32(b, int32(length))
	b = bx.AppendInt16(b, int16(countCols))

	for i := range countCols {
		column := x.Columns[i]
		if column == nil {
			b = bx.AppendInt32(b, -1)
			continue
		}
		lengthCol := len(column)
		b = bx.AppendInt32(b, int32(lengthCol))
		b = bx.AppendByte(b, column...)
	}
	return b, nil
}

func (x *DataRow) UnmarshalBinary(b []byte) error {
	kind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if kind == KindDataRow {
		return unexpectedKind(kind, KindDataRow)
	}

	countCols, b, err := bx.ShiftInt16(b)
	if err != nil {
		return invalidFormat(err)
	}
	columns := make([][]byte, 0, countCols)

	for i := range countCols {
		var length int32
		length, b, err = bx.ShiftInt32(b)
		if err != nil {
			return invalidFormat(err)
		}

		if length == -1 {
			columns[i] = nil
			continue
		}

		columns[i], b, err = bx.ShiftBytes(b, int(length))
		if err != nil {
			return invalidFormat(err)
		}
	}
	return nil
}

var _ Message = &Describe{}
var _ Frontend = &Describe{}

type Describe struct {
	msg
	front

	Kind byte
	Name string
}

func (x *Describe) AppendBinary(b []byte) ([]byte, error) {
	const sizeKind = 1

	length := sizeMessageLength +
		sizeKind +
		len(x.Name) + 1 // null terminated string

	if length > math.MaxInt32 {
		return nil, invalidFormat(bx.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	b = slices.Grow(b, size)
	b = bx.AppendByte(b, KindDescribe)
	b = bx.AppendInt32(b, int32(length))
	b = bx.AppendByte(b, x.Kind)
	b = bx.AppendString(b, x.Name)
	return b, nil
}

func (x *Describe) UnmarshalBinary(b []byte) error {
	msgKind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if msgKind != KindDescribe {
		return unexpectedKind(msgKind, KindDescribe)
	}

	kind, b, err := bx.ShiftByte(b)
	if err != nil {
		return invalidFormat(err)
	}

	name, b, err := bx.ShiftString(b)
	if err != nil {
		return invalidFormat(err)
	}

	x.Kind = kind
	x.Name = name
	return nil
}

var _ Message = &EmptyQueryResponse{}
var _ Backend = &EmptyQueryResponse{}

type EmptyQueryResponse struct {
	msg
	back
}

func (x *EmptyQueryResponse) AppendBinary(b []byte) ([]byte, error) {
	const length = sizeMessageLength
	const size = sizeMessageKind + length

	b = slices.Grow(b, size)
	b = bx.AppendByte(b, KindEmptyQueryResponse)
	b = bx.AppendInt32(b, int32(length))
	return b, nil
}

func (x *EmptyQueryResponse) UnmarshalBinary(b []byte) error {
	kind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if kind != KindEmptyQueryResponse {
		return unexpectedKind(kind, KindEmptyQueryResponse)
	}

	if len(b) > 0 {
		return invalidFormat(bx.ErrValueOverflow)
	}
	return nil
}

type ErrorResponse struct {
	msg
	back

	Fields []byte
	Values []string
}

func (x *ErrorResponse) AppendBinary(b []byte) ([]byte, error) {
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
		return nil, invalidFormat(bx.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	b = slices.Grow(b, size)
	b = bx.AppendByte(b, KindErrorResponse)
	b = bx.AppendInt32(b, int32(length))

	for i := range countFields {
		b = bx.AppendByte(b, x.Fields[i])
		b = bx.AppendString(b, x.Values[i])
	}
	b = bx.AppendByte(b, 0)
	return b, nil
}

func (x *ErrorResponse) UnmarshalBinary(b []byte) error {
	kind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if kind != KindErrorResponse {
		return unexpectedKind(kind, KindErrorResponse)
	}

	var fields []byte
	var values []string

	for {
		var field byte
		field, b, err = bx.ShiftByte(b)
		if err != nil {
			return invalidFormat(err)
		}

		if field == 0 {
			break
		}
		fields = append(fields, field)

		var value string
		value, b, err = bx.ShiftString(b)
		if err != nil {
			return invalidFormat(err)
		}
		values = append(values, value)

		field, b, err = bx.ShiftByte(b)
		if err != nil {
			return invalidFormat(err)
		}
	}

	x.Fields = fields
	x.Values = values
	return nil
}

var _ Message = &Execute{}
var _ Frontend = &Execute{}

type Execute struct {
	msg
	front

	Portal   string
	RowLimit int32
}

func (x *Execute) AppendBinary(b []byte) ([]byte, error) {
	const sizeRowLimit = 4

	sizePortal := len(x.Portal) + 1 // null terminated string

	length := sizeMessageLength + sizePortal + sizeRowLimit

	if length > math.MaxInt32 {
		return nil, invalidFormat(bx.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	b = slices.Grow(b, size)
	b = bx.AppendByte(b, KindExecute)
	b = bx.AppendInt32(b, int32(length))
	b = bx.AppendString(b, x.Portal)
	b = bx.AppendInt32(b, x.RowLimit)
	return b, nil
}

func (x *Execute) UnmarshalBinary(b []byte) error {
	kind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if kind != KindExecute {
		return unexpectedKind(kind, KindExecute)
	}

	portal, b, err := bx.ShiftString(b)
	if err != nil {
		return invalidFormat(err)
	}

	limit, b, err := bx.ShiftInt32(b)
	if err != nil {
		return invalidFormat(err)
	}

	x.Portal = portal
	x.RowLimit = limit
	return nil
}

var _ Message = &Flush{}
var _ Frontend = &Flush{}

type Flush struct {
	msg
	front
}

func (x *Flush) AppendBinary(b []byte) ([]byte, error) {
	const length = sizeMessageLength
	const size = sizeMessageKind + length

	b = slices.Grow(b, size)
	b = bx.AppendByte(b, KindFlush)
	b = bx.AppendInt32(b, int32(length))
	return b, nil
}

func (x *Flush) UnmarshalBinary(b []byte) error {
	kind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if kind != KindFlush {
		return unexpectedKind(kind, KindFlush)
	}

	if len(b) > 0 {
		return invalidFormat(bx.ErrValueOverflow)
	}
	return nil
}

var _ Message = &FunctionCall{}
var _ Frontend = &FunctionCall{}

type FunctionCall struct {
	msg
	front

	ObjectID int32

	// ArgumentFormats may have zero elements, indicating that there are no
	// arguments, or that all arguments use the default format (text); or one,
	// in which case the specified format code is applied to all arguments; or
	// its element count may equal the total number of arguments.
	ArgumentFormats []int16

	ArgumentValues [][]byte
	ResultFormat   int16
}

func (x *FunctionCall) AppendBinary(b []byte) ([]byte, error) {
	const sizeObjectID = 4
	const sizeCountFormats = 2
	const sizeFormat = 2
	const sizeCountArguments = 2
	const sizeArgumentLength = 4
	const sizeResultFormat = 2

	countFormats := len(x.ArgumentFormats)

	if countFormats > math.MaxInt16 {
		return nil, invalidFormat(bx.ErrValueOverflow)
	}

	countArguments := len(x.ArgumentValues)

	if countArguments > math.MaxInt16 {
		return nil, invalidFormat(bx.ErrValueOverflow)
	}

	sizeFormats := countFormats * sizeFormat
	sizeArguments := 0

	for i := range countArguments {
		sizeArgumentValue := len(x.ArgumentValues[i])

		if sizeArgumentValue > math.MaxInt32 {
			return nil, invalidFormat(bx.ErrValueOverflow)
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
		return nil, invalidFormat(bx.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	b = slices.Grow(b, size)
	b = bx.AppendByte(b, KindFunctionCall)
	b = bx.AppendInt32(b, int32(length))
	b = bx.AppendInt32(b, x.ObjectID)
	b = bx.AppendInt16(b, int16(countFormats))
	b = bx.AppendInt16(b, x.ArgumentFormats...)
	b = bx.AppendInt16(b, int16(countArguments))

	for i := range countArguments {
		value := x.ArgumentValues[i]
		length := len(value)
		b = bx.AppendInt32(b, int32(length))
		b = bx.AppendByte(b, value...)
	}
	b = bx.AppendInt16(b, x.ResultFormat)
	return b, nil
}

func (x *FunctionCall) UnmarshalBinary(b []byte) error {
	kind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if kind != KindFunctionCall {
		return unexpectedKind(kind, KindFunctionCall)
	}

	objectID, b, err := bx.ShiftInt32(b)
	if err != nil {
		return invalidFormat(err)
	}

	countFormats, b, err := bx.ShiftInt16(b)
	if err != nil {
		return invalidFormat(err)
	}

	formats := make([]int16, 0, countFormats)
	for range countFormats {
		var format int16
		format, b, err = bx.ShiftInt16(b)
		if err != nil {
			return invalidFormat(err)
		}
		formats = append(formats, format)
	}

	countArguments, b, err := bx.ShiftInt16(b)
	if err != nil {
		return invalidFormat(err)
	}

	arguments := make([][]byte, 0, countArguments)
	for range countArguments {
		var length int32
		length, b, err = bx.ShiftInt32(b)
		if err != nil {
			return invalidFormat(err)
		}
		var value []byte
		value, b, err = bx.ShiftBytes(b, int(length))
		if err != nil {
			return invalidFormat(err)
		}
		arguments = append(arguments, value)
	}
	resultFormat, b, err := bx.ShiftInt16(b)
	if err != nil {
		return invalidFormat(err)
	}
	x.ObjectID = objectID
	x.ArgumentFormats = formats
	x.ArgumentValues = arguments
	x.ResultFormat = resultFormat
	return nil
}

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
		return nil, invalidFormat(bx.ErrValueOverflow)
	}

	length := sizeMessageLength +
		sizeResultLength +
		sizeResult

	size := sizeMessageKind + length

	b = slices.Grow(b, size)
	b = bx.AppendByte(b, KindFunctionCallResponse)
	b = bx.AppendInt32(b, int32(length))

	if x.Result == nil {
		b = bx.AppendInt32(b, int32(-1))
	} else {
		b = bx.AppendInt32(b, int32(sizeResult))
	}
	b = bx.AppendByte(b, x.Result...)
	return b, nil
}

func (x *FunctionCallResponse) UnmarshalBinary(b []byte) error {
	kind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if kind != KindFunctionCallResponse {
		return unexpectedKind(kind, KindFunctionCall)
	}

	length, b, err := bx.ShiftInt32(b)
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

var _ Message = &GSSENCRequest{}
var _ Frontend = &GSSENCRequest{}

const (
	encHigh               int32 = 1234
	encLow                int32 = 5680
	CodeEncryptionRequest int32 = encLow | encHigh<<16
)

type GSSENCRequest struct {
	msg
	front
}

func (x *GSSENCRequest) AppendBinary(b []byte) ([]byte, error) {
	const sizeCode = 4
	const length = sizeMessageLength + sizeCode

	b = slices.Grow(b, length)
	b = bx.AppendInt32(b, length)
	b = bx.AppendInt32(b, CodeEncryptionRequest)
	return b, nil
}

func (x *GSSENCRequest) UnmarshalBinary(b []byte) error {
	b, err := ShiftLength(b)
	if err != nil {
		return invalidFormat(err)
	}

	code, b, err := bx.ShiftInt32(b)
	if err != nil {
		return invalidFormat(err)
	}

	if code != CodeEncryptionRequest {
		return invalidFormat(bx.ErrUnknownCode)
	}
	return nil
}

var _ Message = &GSSResponse{}
var _ Frontend = &GSSResponse{}

type GSSResponse struct {
	msg
	front

	Data []byte
}

func (x *GSSResponse) AppendBinary(b []byte) ([]byte, error) {
	length := sizeMessageLength + len(x.Data)

	if length > math.MaxInt32 {
		return nil, invalidFormat(bx.ErrValueOverflow)
	}
	size := sizeMessageKind + length

	b = slices.Grow(b, size)
	b = bx.AppendByte(b, KindGSSResponse)
	b = bx.AppendInt32(b, int32(length))
	b = bx.AppendByte(b, x.Data...)
	return b, nil
}

func (x *GSSResponse) UnmarshalBinary(b []byte) error {
	kind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if kind != KindGSSResponse {
		return unexpectedKind(kind, KindGSSResponse)
	}

	x.Data = make([]byte, len(b))
	copy(x.Data, b)
	return nil
}

var _ Message = &NegotiateProtocolVersion{}
var _ Backend = &NegotiateProtocolVersion{}

type NegotiateProtocolVersion struct {
	msg
	back

	MinorVersionSupported int32
	UnrecognizedOptions   []string
}

func (x *NegotiateProtocolVersion) AppendBinary(b []byte) ([]byte, error) {
	const sizeMinorVersion = 4
	const sizeUnrecognizedOptionCount = 4

	length := sizeMessageLength +
		sizeMinorVersion +
		sizeUnrecognizedOptionCount

	countUnrecognizedOptions := len(x.UnrecognizedOptions)

	if countUnrecognizedOptions > math.MaxInt32 {
		return nil, invalidFormat(bx.ErrValueOverflow)
	}

	for _, option := range x.UnrecognizedOptions {
		length += len(option)
	}

	if length > math.MaxInt32 {
		return nil, invalidFormat(bx.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	b = slices.Grow(b, size)
	b = bx.AppendByte(b, KindNegotiateProtocolVersion)
	b = bx.AppendInt32(b, int32(length))
	b = bx.AppendInt32(b, x.MinorVersionSupported)
	b = bx.AppendInt32(b, int32(countUnrecognizedOptions))
	b = bx.AppendString(b, x.UnrecognizedOptions...)
	return b, nil
}

func (x *NegotiateProtocolVersion) UnmarshalBinary(b []byte) error {
	kind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if kind != KindNegotiateProtocolVersion {
		return unexpectedKind(kind, KindNegotiateProtocolVersion)
	}

	minorVersion, b, err := bx.ShiftInt32(b)
	if err != nil {
		return invalidFormat(err)
	}

	countUnsupportedOptions, b, err := bx.ShiftInt32(b)
	if err != nil {
		return invalidFormat(err)
	}

	options := make([]string, 0, countUnsupportedOptions)

	for range countUnsupportedOptions {
		var option string
		option, b, err = bx.ShiftString(b)
		if err != nil {
			return invalidFormat(err)
		}
		options = append(options, option)
	}
	x.MinorVersionSupported = minorVersion
	x.UnrecognizedOptions = options
	return nil
}

var _ Message = &NoData{}
var _ Backend = &NoData{}

type NoData struct {
	msg
	back
}

func (x *NoData) AppendBinary(b []byte) ([]byte, error) {
	const length = sizeMessageLength
	const size = sizeMessageKind + length

	b = slices.Grow(b, size)
	b = bx.AppendByte(b, KindNoData)
	b = bx.AppendInt32(b, length)
	return b, nil
}

func (x *NoData) UnmarshalBinary(b []byte) error {
	kind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if kind != KindNoData {
		return unexpectedKind(kind, KindNoData)
	}

	if len(b) > 0 {
		return invalidFormat(bx.ErrValueOverflow)
	}
	return nil
}

type NoticeResponse struct {
	Fields []byte
	Values []string
}

func (x *NoticeResponse) Encode(w io.Writer) error {
	var buf bytes.Buffer
	for i := range len(x.Fields) {
		_ = writeByte(&buf, x.Fields[i])
		_ = writeString(&buf, x.Values[i])
	}
	_ = writeByte(&buf, 0)
	return writeMessage(w, msgKindNoticeResponse, buf.Bytes())
}

func (x *NoticeResponse) Decode(b []byte) error {
	var field byte
	bread, err := readByte(b, &field)
	if err != nil {
		return err
	}
	b = b[bread:]

	for field != 0 {
		x.Fields = append(x.Fields, field)
		var value string
		bread, err = readString(b, &value)
		if err != nil {
			return err
		}
		b = b[bread:]
		x.Values = append(x.Values, value)
		bread, err = readByte(b, &field)
		if err != nil {
			return err
		}
		b = b[bread:]
	}
	return nil
}

type MsgNotificationResponse struct {
	ProcessID int32
	Channel   string
	Payload   string
}

func (x *MsgNotificationResponse) Encode(w io.Writer) error {
	var buf bytes.Buffer
	_ = writeInt32(&buf, x.ProcessID)
	_ = writeString(&buf, x.Channel)
	_ = writeString(&buf, x.Payload)
	return writeMessage(w, msgKindNotificationResponse, buf.Bytes())
}

func (x *MsgNotificationResponse) Decode(b []byte) error {
	bread, err := readInt32(b, &x.ProcessID)
	if err != nil {
		return err
	}
	b = b[bread:]

	bread, err = readString(b, &x.Channel)
	if err != nil {
		return err
	}
	b = b[bread:]

	_, err = readString(b, &x.Payload)
	if err != nil {
		return err
	}
	return nil
}

type MsgParameterDescription struct {
	Parameters []int32
}

func (x *MsgParameterDescription) Encode(w io.Writer) error {
	var buf bytes.Buffer
	_ = writeInt16(&buf, int16(len(x.Parameters)))
	for _, param := range x.Parameters {
		_ = writeInt32(&buf, param)
	}
	return writeMessage(w, msgKindParameterDescription, buf.Bytes())
}

func (x *MsgParameterDescription) Decode(b []byte) error {
	var length int16
	bread, err := readInt16(b, &length)
	if err != nil {
		return err
	}
	b = b[bread:]

	x.Parameters = make([]int32, length)

	for i := range length {
		var param int32
		bread, err = readInt32(b, &param)
		if err != nil {
			return err
		}
		x.Parameters[i] = param
		b = b[bread:]
	}
	return nil
}

type MsgParameterStatus struct {
	Name  string
	Value string
}

func (x *MsgParameterStatus) Encode(w io.Writer) error {
	var buf bytes.Buffer
	_ = writeString(&buf, x.Name)
	_ = writeString(&buf, x.Value)
	return writeMessage(w, msgKindParameterStatus, buf.Bytes())
}

func (x *MsgParameterStatus) Decode(b []byte) error {
	bread, err := readString(b, &x.Name)
	if err != nil {
		return err
	}
	b = b[bread:]

	_, err = readString(b, &x.Value)
	if err != nil {
		return err
	}
	return nil
}

type MsgParseComplete struct{}

func (x *MsgParseComplete) Encode(w io.Writer) error {
	return writeMessage(w, msgKindParseComplete, []byte{})
}

func (x *MsgParseComplete) Decode(_ []byte) error {
	return nil
}

type MsgPortalSuspended struct{}

func (x *MsgPortalSuspended) Encode(w io.Writer) error {
	return writeMessage(w, msgKindPortalSuspended, []byte{})
}

func (x *MsgPortalSuspended) Decode(_ []byte) error {
	return nil
}

type MsgReadyForQuery struct {
	TxStatus byte
}

func (x *MsgReadyForQuery) Encode(w io.Writer) error {
	var buf bytes.Buffer
	_ = writeByte(&buf, x.TxStatus)
	return writeMessage(w, msgKindReadyForQuery, buf.Bytes())
}

func (x *MsgReadyForQuery) Decode(b []byte) error {
	_, err := readByte(b, &x.TxStatus)
	if err != nil {
		return err
	}
	return nil
}

type MsgRowDescription struct {
	Names     []string
	Tables    []int32
	Columns   []int16
	DataTypes []int32
	Sizes     []int16
	Modifiers []int32
	Formats   []int16
}

func (x *MsgRowDescription) Encode(w io.Writer) error {
	var buf bytes.Buffer
	_ = writeInt16(&buf, int16(len(x.Names)))
	for i := range len(x.Names) {
		_ = writeString(&buf, x.Names[i])
		_ = writeInt32(&buf, x.Tables[i])
		_ = writeInt16(&buf, x.Columns[i])
		_ = writeInt32(&buf, x.DataTypes[i])
		_ = writeInt16(&buf, x.Sizes[i])
		_ = writeInt32(&buf, x.Modifiers[i])
		_ = writeInt16(&buf, x.Formats[i])
	}
	return writeMessage(w, msgKindRowDescription, buf.Bytes())
}

func (x *MsgRowDescription) Decode(b []byte) error {
	var length int16
	bread, err := readInt16(b, &length)
	if err != nil {
		return err
	}
	b = b[bread:]

	x.Names = make([]string, length)
	x.Tables = make([]int32, length)
	x.Columns = make([]int16, length)
	x.DataTypes = make([]int32, length)
	x.Sizes = make([]int16, length)
	x.Modifiers = make([]int32, length)
	x.Formats = make([]int16, length)

	for i := range length {
		bread, err := readString(b, &x.Names[i])
		if err != nil {
			return err
		}
		b = b[bread:]

		bread, err = readInt32(b, &x.Tables[i])
		if err != nil {
			return err
		}
		b = b[bread:]

		bread, err = readInt16(b, &x.Columns[i])
		if err != nil {
			return err
		}
		b = b[bread:]

		bread, err = readInt32(b, &x.DataTypes[i])
		if err != nil {
			return err
		}
		b = b[bread:]

		bread, err = readInt16(b, &x.Sizes[i])
		if err != nil {
			return err
		}
		b = b[bread:]

		bread, err = readInt32(b, &x.Modifiers[i])
		if err != nil {
			return err
		}
		b = b[bread:]

		bread, err = readInt16(b, &x.Formats[i])
		if err != nil {
			return err
		}
		b = b[bread:]
	}
	return nil
}

type MsgUnknown struct{}

func (x *MsgUnknown) Encode(_ io.Writer) error {
	return ErrUnknownMessageType
}

func (x *MsgUnknown) Decode(_ []byte) error {
	return ErrUnknownMessageType
}

type MsgUnknownAuth struct{}

func (x *MsgUnknownAuth) Encode(_ io.Writer) error {
	return ErrUnknownAuthType
}

func (x *MsgUnknownAuth) Decode(_ []byte) error {
	return ErrUnknownAuthType
}

package msg

import (
	"bytes"
	"encoding"
	"errors"
	"fmt"
	"gopsql/internal/bx"
	"io"
	"math"
)

const (
	CodeCancelRequest int32 = 80877102
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
	KindCopyInResponse           byte = 'G'
	KindCopyOutResponse          byte = 'H'
	KindCopyBothResponse         byte = 'W'
	KindDataRow                  byte = 'D'
	KindEmptyQueryResponse       byte = 'I'
	KindErrorResponse            byte = 'E'
	KindFunctionCallResponse     byte = 'V'
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
	KindAuthOk                int32 = 0
	KindAuthKerberosV5        int32 = 2
	KindAuthCleartextPassword int32 = 3
	KindAuthMD5Password       int32 = 5
	KindAuthGSS               int32 = 7
	KindAuthGSSContinue       int32 = 8
	KindAuthSSPI              int32 = 9
	KindAuthSASL              int32 = 10
	KindAuthSASLContinue      int32 = 11
	KindAuthSASLFinal         int32 = 12
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

var _ Message = &AuthOk{}
var _ Backend = &AuthOk{}

type AuthOk struct {
	msg
	back
}

func (x *AuthOk) AppendBinary(b []byte) ([]byte, error) {
	b = bx.AppendByte(b, KindAuthentication)
	b = bx.AppendInt32(b, 8)
	b = bx.AppendInt32(b, KindAuthOk)
	return b, nil
}

func (x *AuthOk) UnmarshalBinary(b []byte) error {
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

	if authKind != KindAuthOk {
		return unexpectedAuthKind(authKind, KindAuthOk)
	}

	if len(b) > 0 {
		return bx.ErrValueOverflow
	}
	return nil
}

var _ Message = &AuthKerberosV5{}
var _ Backend = &AuthKerberosV5{}

type AuthKerberosV5 struct {
	msg
	back
}

func (x *AuthKerberosV5) AppendBinary(b []byte) ([]byte, error) {
	b = bx.AppendByte(b, KindAuthentication)
	b = bx.AppendInt32(b, 8)
	b = bx.AppendInt32(b, KindAuthKerberosV5)
	return b, nil
}

func (x *AuthKerberosV5) UnmarshalBinary(b []byte) error {
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

	if authKind != KindAuthKerberosV5 {
		return unexpectedAuthKind(authKind, KindAuthKerberosV5)
	}

	if len(b) > 0 {
		return invalidFormat(bx.ErrValueOverflow)
	}
	return nil
}

var _ Message = &AuthCleartextPassword{}
var _ Backend = &AuthCleartextPassword{}

type AuthCleartextPassword struct {
	msg
	back
}

func (x *AuthCleartextPassword) AppendBinary(b []byte) ([]byte, error) {
	b = bx.AppendByte(b, KindAuthentication)
	b = bx.AppendInt32(b, 8)
	b = bx.AppendInt32(b, KindAuthCleartextPassword)
	return b, nil
}

func (x *AuthCleartextPassword) UnmarshalBinary(b []byte) error {
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

	if authKind != KindAuthCleartextPassword {
		return unexpectedAuthKind(authKind, KindAuthCleartextPassword)
	}

	if len(b) > 0 {
		return invalidFormat(bx.ErrValueOverflow)
	}
	return nil
}

var _ Message = &AuthMD5Password{}
var _ Backend = &AuthMD5Password{}

type AuthMD5Password struct {
	msg
	back

	Salt [4]byte
}

func (x *AuthMD5Password) AppendBinary(b []byte) ([]byte, error) {
	b = bx.AppendByte(b, KindAuthentication)
	b = bx.AppendInt32(b, 12)
	b = bx.AppendInt32(b, KindAuthMD5Password)
	b = bx.AppendBytes(b, x.Salt[:])
	return b, nil
}

func (x *AuthMD5Password) UnmarshalBinary(b []byte) error {
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

	if authKind != KindAuthMD5Password {
		return unexpectedAuthKind(authKind, KindAuthMD5Password)
	}
	copy(x.Salt[:], b)
	return nil
}

var _ Message = &AuthGSS{}
var _ Backend = &AuthGSS{}

type AuthGSS struct {
	msg
	back
}

func (x *AuthGSS) AppendBinary(b []byte) ([]byte, error) {
	b = bx.AppendByte(b, KindAuthentication)
	b = bx.AppendInt32(b, 8)
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
	b = bx.AppendByte(b, KindAuthentication)
	b = bx.AppendInt32(b, int32(8+len(x.Data)))
	b = bx.AppendInt32(b, KindAuthGSSContinue)
	b = bx.AppendBytes(b, x.Data)
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
	b = bx.AppendByte(b, KindAuthentication)
	b = bx.AppendInt32(b, 8)
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
	b = bx.AppendByte(b, KindAuthentication)

	var mechanisms []byte

	mechanisms = bx.AppendInt32(mechanisms, KindAuthSASL)

	for i := range len(x.Mechanisms) {
		mechanisms = bx.AppendString(mechanisms, x.Mechanisms[i])
	}
	mechanisms = bx.AppendByte(mechanisms, 0x0)

	b = bx.AppendInt32(b, int32(4+len(mechanisms)))
	b = bx.AppendBytes(b, mechanisms)
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
	x.Mechanisms = []string{}

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
	b = bx.AppendByte(b, KindAuthentication)
	b = bx.AppendInt32(b, int32(8+len(x.Data)))
	b = bx.AppendInt32(b, KindAuthSASLContinue)
	b = bx.AppendBytes(b, x.Data)
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
	b = bx.AppendByte(b, KindAuthentication)
	b = bx.AppendInt32(b, int32(8+len(x.Data)))
	b = bx.AppendInt32(b, KindAuthSASLFinal)
	b = bx.AppendBytes(b, x.Data)
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
	b = bx.AppendByte(b, KindBackendKeyData)
	b = bx.AppendInt32(b, int32(8+len(x.SecretKey)))
	b = bx.AppendInt32(b, x.ProcessID)
	b = bx.AppendBytes(b, x.SecretKey)
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
	var buffer []byte

	buffer = bx.AppendString(buffer, x.DestinationName)
	buffer = bx.AppendString(buffer, x.SourceName)

	paramFmtCodeCount := len(x.ParameterFormatCodes)
	if paramFmtCodeCount > math.MaxInt16 {
		return nil, invalidFormat(bx.ErrValueOverflow)
	}
	buffer = bx.AppendInt16(buffer, int16(paramFmtCodeCount))

	for i := range paramFmtCodeCount {
		buffer = bx.AppendInt16(buffer, x.ParameterFormatCodes[i])
	}

	paramDataCount := len(x.ParameterData)
	if paramDataCount > math.MaxInt16 {
		return nil, invalidFormat(bx.ErrValueOverflow)
	}
	buffer = bx.AppendInt16(buffer, int16(paramDataCount))

	for i := range paramDataCount {
		dataLen := len(x.ParameterData[i])
		if dataLen > math.MaxInt32 {
			return nil, invalidFormat(bx.ErrValueOverflow)
		}
		buffer = bx.AppendInt32(buffer, int32(dataLen))
		buffer = bx.AppendBytes(buffer, x.ParameterData[i])
	}

	colFmtCodeCount := len(x.ColumnFormatCodes)
	if colFmtCodeCount > math.MaxInt16 {
		return nil, invalidFormat(bx.ErrValueOverflow)
	}
	buffer = bx.AppendInt16(buffer, int16(colFmtCodeCount))

	for i := range colFmtCodeCount {
		buffer = bx.AppendInt16(buffer, x.ColumnFormatCodes[i])
	}

	b = bx.AppendByte(b, KindBind)
	b = bx.AppendInt32(b, int32(4+len(buffer)))
	b = bx.AppendBytes(b, buffer)
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
	b = bx.AppendByte(b, KindBindComplete)
	b = bx.AppendInt32(b, 4)
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

type CancelRequest struct {
	msg
	front

	ProcessID int32
	SecretKey []byte
}

func (x *CancelRequest) AppendBinary(b []byte) ([]byte, error) {
	if len(x.SecretKey) > 256 {
		return nil, invalidFormat(bx.ErrValueOverflow)
	}
	var buffer []byte
	buffer = bx.AppendInt32(buffer, CodeCancelRequest)
	buffer = bx.AppendInt32(buffer, x.ProcessID)
	buffer = bx.AppendBytes(buffer, x.SecretKey)

	if len(buffer) > math.MaxInt32 {
		return nil, invalidFormat(bx.ErrValueOverflow)
	}

	b = bx.AppendInt32(b, int32(len(buffer)+4))
	b = bx.AppendBytes(b, buffer)
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
	var buffer []byte
	buffer = bx.AppendByte(buffer, x.Kind)
	buffer = bx.AppendString(buffer, x.Name)

	b = bx.AppendByte(b, KindClose)
	b = bx.AppendInt32(b, int32(len(buffer))+4)
	b = bx.AppendBytes(b, buffer)
	return b, nil
}

func (x *Close) UnmarshalBinary(b []byte) error {
	msgKind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if msgKind != KindClose {
		return unexpectedKind(KindClose)
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
	b = bx.AppendByte(b, KindCloseComplete)
	b = bx.AppendInt32(b, 4)
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
	b = bx.AppendByte(b, KindCommandComplete)
	b = bx.AppendInt32(b, int32(len(x.Tag))+4)
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
	b = bx.AppendByte(b, KindCopyData)
	b = bx.AppendInt32(b, int32(len(x.Data)+4))
	b = bx.AppendBytes(b, x.Data)
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
	b = bx.AppendByte(b, KindCopyDone)
	b = bx.AppendInt32(b, 4)
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

type MsgCopyInResponse struct {
	Format  int8
	Columns []int16
}

func (x *MsgCopyInResponse) Encode(w io.Writer) error {
	var buf bytes.Buffer
	_ = writeInt8(&buf, x.Format)
	_ = writeInt16(&buf, int16(len(x.Columns)))
	for _, f := range x.Columns {
		_ = writeInt16(&buf, f)
	}
	return writeMessage(w, msgKindCopyInResponse, buf.Bytes())
}

func (x *MsgCopyInResponse) Decode(b []byte) error {
	bread, err := readInt8(b, &x.Format)
	if err != nil {
		return err
	}
	b = b[bread:]

	var columns int16
	bread, err = readInt16(b, &columns)
	if err != nil {
		return err
	}
	b = b[bread:]

	if len(b) < int(columns)*2 {
		return ErrValueUnderflow
	}

	x.Columns = make([]int16, int(columns))
	for i := range columns {
		bread, err = readInt16(b, &x.Columns[i])
		if err != nil {
			return err
		}
		b = b[bread:]
	}
	return nil
}

type MsgCopyOutResponse struct {
	Format  int8
	Columns []int16
}

func (x *MsgCopyOutResponse) Encode(w io.Writer) error {
	var buf bytes.Buffer
	_ = writeInt8(&buf, x.Format)
	_ = writeInt16(&buf, int16(len(x.Columns)))
	for _, f := range x.Columns {
		_ = writeInt16(&buf, f)
	}
	return writeMessage(w, msgKindCopyOutResponse, buf.Bytes())
}

func (x *MsgCopyOutResponse) Decode(b []byte) error {
	bread, err := readInt8(b, &x.Format)
	if err != nil {
		return err
	}
	b = b[bread:]

	var columns int16
	bread, err = readInt16(b, &columns)
	if err != nil {
		return err
	}
	b = b[bread:]

	if len(b) < int(columns)*2 {
		return ErrValueUnderflow
	}

	x.Columns = make([]int16, int(columns))
	for i := range columns {
		bread, err = readInt16(b, &x.Columns[i])
		if err != nil {
			return err
		}
		b = b[bread:]
	}
	return nil
}

type MsgCopyBothResponse struct {
	Format  int8
	Columns []int16
}

func (x *MsgCopyBothResponse) Encode(w io.Writer) error {
	var buf bytes.Buffer
	_ = writeInt8(&buf, x.Format)
	_ = writeInt16(&buf, int16(len(x.Columns)))
	for _, f := range x.Columns {
		_ = writeInt16(&buf, f)
	}
	return writeMessage(w, msgKindCopyBothResponse, buf.Bytes())
}

func (x *MsgCopyBothResponse) Decode(b []byte) error {
	bread, err := readInt8(b, &x.Format)
	if err != nil {
		return err
	}
	b = b[bread:]

	var columns int16
	bread, err = readInt16(b, &columns)
	if err != nil {
		return err
	}
	b = b[bread:]

	if len(b) < int(columns)*2 {
		return ErrValueUnderflow
	}

	x.Columns = make([]int16, int(columns))
	for i := range columns {
		bread, err = readInt16(b, &x.Columns[i])
		if err != nil {
			return err
		}
		b = b[bread:]
	}
	return nil
}

type MsgDataRow struct {
	// First dimention is columns (can have 0 elements).
	// Second dimension is value data (can have 0 elements
	// or be nil).
	Columns [][]byte
}

func (x *MsgDataRow) Encode(w io.Writer) error {
	var buf bytes.Buffer
	_ = writeInt16(&buf, int16(len(x.Columns)))
	for _, column := range x.Columns {
		if column == nil {
			_ = writeInt32(&buf, -1)
			continue
		}
		_ = writeInt32(&buf, int32(len(column)))
		_ = writeBytes(&buf, column)
	}
	return writeMessage(w, msgKindDataRow, buf.Bytes())
}

func (x *MsgDataRow) Decode(b []byte) error {
	var columns int16
	bread, err := readInt16(b, &columns)
	if err != nil {
		return err
	}
	b = b[bread:]
	x.Columns = make([][]byte, columns)

	for i := range columns {
		var length int32
		bread, err = readInt32(b, &length)
		if err != nil {
			return err
		}
		b = b[bread:]

		if length == -1 {
			x.Columns[i] = nil
			continue
		}
		x.Columns[i] = make([]byte, length)
		copy(x.Columns[i], b[:length])
		b = b[length:]
	}
	return nil
}

type MsgEmptyQueryResponse struct{}

func (x *MsgEmptyQueryResponse) Encode(w io.Writer) error {
	return writeMessage(w, msgKindEmptyQueryResponse, []byte{})
}

func (x *MsgEmptyQueryResponse) Decode(_ []byte) error {
	return nil
}

type MsgErrorResponse struct {
	Fields []byte
	Values []string
}

func (x *MsgErrorResponse) Encode(w io.Writer) error {
	var buf bytes.Buffer
	for i := range len(x.Fields) {
		_ = writeByte(&buf, x.Fields[i])
		_ = writeString(&buf, x.Values[i])
	}
	_ = writeByte(&buf, 0)
	return writeMessage(w, msgKindErrorResponse, buf.Bytes())
}

func (x *MsgErrorResponse) Decode(b []byte) error {
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

type MsgFunctionCallResponse struct {
	// Can be zero length or nil.
	Result []byte
}

func (x *MsgFunctionCallResponse) Encode(w io.Writer) error {
	var buf bytes.Buffer
	if x.Result == nil {
		_ = writeInt32(&buf, -1)
	} else {
		_ = writeInt32(&buf, int32(len(x.Result)))
	}
	_ = writeBytes(&buf, x.Result)
	return writeMessage(w, msgKindFunctionCallResponse, buf.Bytes())
}

func (x *MsgFunctionCallResponse) Decode(b []byte) error {
	var length int32
	bread, err := readInt32(b, &length)
	if err != nil {
		return err
	}
	b = b[bread:]

	if length >= 0 {
		x.Result = make([]byte, length)
		copy(x.Result, b[:length])
	}
	// f.Result remains nil when length < 0
	return nil
}

type MsgNegotiateProtocolVersion struct {
	MinorVersionSupported int32
	UnrecognizedOptions   []string
}

func (x *MsgNegotiateProtocolVersion) Encode(w io.Writer) error {
	var buf bytes.Buffer
	_ = writeInt32(&buf, x.MinorVersionSupported)
	_ = writeInt32(&buf, int32(len(x.UnrecognizedOptions)))
	for _, option := range x.UnrecognizedOptions {
		_ = writeString(&buf, option)
	}
	return writeMessage(w, msgKindNegotiateProtocolVersion, buf.Bytes())
}

func (x *MsgNegotiateProtocolVersion) Decode(b []byte) error {
	bread, err := readInt32(b, &x.MinorVersionSupported)
	if err != nil {
		return err
	}
	b = b[bread:]

	var numUnrecognized int32
	bread, err = readInt32(b, &numUnrecognized)
	if err != nil {
		return err
	}
	b = b[bread:]

	x.UnrecognizedOptions = make([]string, numUnrecognized)

	for i := range numUnrecognized {
		var protocol string
		bread, err = readString(b, &protocol)
		if err != nil {
			return nil
		}
		b = b[bread:]
		x.UnrecognizedOptions[i] = protocol
	}
	return nil
}

type MsgNoData struct{}

func (x *MsgNoData) Encode(w io.Writer) error {
	return writeMessage(w, msgKindNoData, []byte{})
}

func (x *MsgNoData) Decode(_ []byte) error {
	return nil
}

type MsgNoticeResponse struct {
	Fields []byte
	Values []string
}

func (x *MsgNoticeResponse) Encode(w io.Writer) error {
	var buf bytes.Buffer
	for i := range len(x.Fields) {
		_ = writeByte(&buf, x.Fields[i])
		_ = writeString(&buf, x.Values[i])
	}
	_ = writeByte(&buf, 0)
	return writeMessage(w, msgKindNoticeResponse, buf.Bytes())
}

func (x *MsgNoticeResponse) Decode(b []byte) error {
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

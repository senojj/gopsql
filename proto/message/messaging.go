package backend

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

var (
	ErrValueUnderflow = errors.New("partial value")
	ErrValueOverflow  = errors.New("value too large")
	ErrInvalidValue   = errors.New("invalid value")
)

type Kind byte

const (
	KindAuthentication           Kind = 'R'
	KindKeyData                  Kind = 'K'
	KindBindComplete             Kind = '2'
	KindCloseComplete            Kind = '3'
	KindCommandComplete          Kind = 'C'
	KindCopyData                 Kind = 'd'
	KindCopyDone                 Kind = 'c'
	KindCopyInResponse           Kind = 'G'
	KindCopyOutResponse          Kind = 'H'
	KindCopyBothResponse         Kind = 'W'
	KindDataRow                  Kind = 'D'
	KindEmptyQueryResponse       Kind = 'I'
	KindErrorResponse            Kind = 'E'
	KindFunctionCallResponse     Kind = 'V'
	KindNegotiateProtocolVersion Kind = 'v'
	KindNoData                   Kind = 'n'
	KindNoticeResponse           Kind = 'N'
	KindNotificationResponse     Kind = 'A'
	KindParameterDescription     Kind = 't'
	KindParameterStatus          Kind = 'S'
	KindParseComplete            Kind = '1'
	KindPortalSuspended          Kind = 's'
	KindReadyForQuery            Kind = 'Z'
	KindRowDescription           Kind = 'T'
)

func ParseKind(b byte) (Kind, error) {
	var err error
	v := Kind(b)

	switch v {
	case KindAuthentication:
	case KindKeyData:
	case KindBindComplete:
	case KindCloseComplete:
	case KindCommandComplete:
	case KindCopyData:
	case KindCopyDone:
	case KindCopyInResponse:
	case KindCopyOutResponse:
	case KindCopyBothResponse:
	case KindDataRow:
	case KindEmptyQueryResponse:
	case KindErrorResponse:
	case KindFunctionCallResponse:
	case KindNegotiateProtocolVersion:
	case KindNoData:
	case KindNoticeResponse:
	case KindNotificationResponse:
	case KindParameterDescription:
	case KindParameterStatus:
	case KindParseComplete:
	case KindPortalSuspended:
	case KindReadyForQuery:
	case KindRowDescription:
	default:
		err = ErrInvalidValue
	}
	return v, err
}

type AuthKind int32

const (
	AuthKindOk                AuthKind = 0
	AuthKindKerberosV5        AuthKind = 2
	AuthKindCleartextPassword AuthKind = 3
	AuthKindMD5Password       AuthKind = 5
	AuthKindGSS               AuthKind = 7
	AuthKindGSSContinue       AuthKind = 8
	AuthKindSSPI              AuthKind = 9
	AuthKindSASL              AuthKind = 10
	AuthKindSASLContinue      AuthKind = 11
	AuthKindSASLFinal         AuthKind = 12
)

func ParseAuthKind(i int32) (AuthKind, error) {
	var err error
	v := AuthKind(i)

	switch v {
	case AuthKindOk:
	case AuthKindKerberosV5:
	case AuthKindCleartextPassword:
	case AuthKindMD5Password:
	case AuthKindGSS:
	case AuthKindGSSContinue:
	case AuthKindSSPI:
	case AuthKindSASL:
	case AuthKindSASLContinue:
	case AuthKindSASLFinal:
	default:
		err = ErrInvalidValue
	}
	return v, err
}

type Field byte

const (
	FieldSeverity         Field = 'S'
	FieldSeverityRaw      Field = 'V'
	FieldCode             Field = 'C'
	FieldMessage          Field = 'M'
	FieldDetail           Field = 'D'
	FieldHint             Field = 'H'
	FieldPosition         Field = 'P'
	FieldInternalPosition Field = 'p'
	FieldInternalQuery    Field = 'q'
	FieldWhere            Field = 'W'
	FieldSchema           Field = 's'
	FieldTable            Field = 't'
	FieldColumn           Field = 'c'
	FieldDataType         Field = 'd'
	FieldConstraint       Field = 'n'
	FieldFile             Field = 'F'
	FieldLine             Field = 'L'
	FieldRoutine          Field = 'R'
)

func ParseField(b byte) (Field, error) {
	var err error
	v := Field(b)

	switch v {
	case FieldSeverity:
	case FieldSeverityRaw:
	case FieldCode:
	case FieldMessage:
	case FieldDetail:
	case FieldHint:
	case FieldPosition:
	case FieldInternalPosition:
	case FieldInternalQuery:
	case FieldWhere:
	case FieldSchema:
	case FieldTable:
	case FieldColumn:
	case FieldDataType:
	case FieldConstraint:
	case FieldFile:
	case FieldLine:
	case FieldRoutine:
	default:
		err = ErrInvalidValue
	}
	return v, err
}

type Format int16

const (
	FormatText   Format = 0
	FormatBinary Format = 1
)

func ParseFormat(i int16) (Format, error) {
	var err error
	v := Format(i)

	switch v {
	case FormatText:
	case FormatBinary:
	default:
		err = ErrInvalidValue
	}
	return v, err
}

type TxStatus byte

const (
	TxStatusIdle   TxStatus = 'I'
	TxStatusActive TxStatus = 'T'
	TxStatusError  TxStatus = 'E'
)

func ParseTxStatus(b byte) (TxStatus, error) {
	var err error
	v := TxStatus(b)

	switch v {
	case TxStatusIdle:
	case TxStatusActive:
	case TxStatusError:
	default:
		err = ErrInvalidValue
	}
	return v, err
}

type xAuthentication struct {
	kind AuthKind
	data []byte
}

func (x *xAuthentication) Encode() ([]byte, error) {
	var buf bytes.Buffer

	writeAuthKind(&buf, x.kind)
	writeBytes(&buf, x.data)

	var msg xMessage
	msg.kind = KindAuthentication
	msg.data = buf.Bytes()

	return msg.Encode()
}

func (x *xAuthentication) Decode(b []byte) error {
	bread, err := readAuthKind(b, &x.kind)
	if err != nil {
		return err
	}
	b = b[bread:]

	x.data = make([]byte, len(b))
	copy(x.data, b)
	return nil
}

func (a *xAuthentication) Parse() (any, error) {
	switch a.kind {
	case AuthKindOk:
		var x xAuthenticationOk
		err := x.Decode(a.data)
		return AuthenticationOk(x), err
	case AuthKindKerberosV5:
		var x xAuthenticationKerberosV5
		err := x.Decode(a.data)
		return AuthenticationKerberosV5(x), err
	case AuthKindCleartextPassword:
		var x xAuthenticationCleartextPassword
		err := x.Decode(a.data)
		return AuthenticationCleartextPassword(x), err
	case AuthKindMD5Password:
		var x xAuthenticationMD5Password
		err := x.Decode(a.data)
		return AuthenticationMD5Password(x), err
	case AuthKindGSS:
		var x xAuthenticationGSS
		err := x.Decode(a.data)
		return AuthenticationGSS(x), err
	case AuthKindGSSContinue:
		var x xAuthenticationGSSContinue
		err := x.Decode(a.data)
		return AuthenticationGSSContinue(x), err
	case AuthKindSSPI:
		var x xAuthenticationSSPI
		err := x.Decode(a.data)
		return AuthenticationSSPI(x), err
	case AuthKindSASL:
		var x xAuthenticationSASL
		err := x.Decode(a.data)
		return AuthenticationSASL(x), err
	case AuthKindSASLContinue:
		var x xAuthenticationSASLContinue
		err := x.Decode(a.data)
		return AuthenticationSASLContinue(x), err
	case AuthKindSASLFinal:
		var x xAuthenticationSASLFinal
		err := x.Decode(a.data)
		return AuthenticationSASLFinal(x), err
	default:
		return Unknown{}, nil
	}
}

type AuthenticationOk struct{}

type xAuthenticationOk AuthenticationOk

func (x *xAuthenticationOk) Encode() ([]byte, error) {
	var auth xAuthentication
	auth.kind = AuthKindOk
	auth.data = []byte{}

	return auth.Encode()
}

func (x *xAuthenticationOk) Decode(_ []byte) error {
	return nil
}

type AuthenticationKerberosV5 struct{}

type xAuthenticationKerberosV5 AuthenticationKerberosV5

func (x *xAuthenticationKerberosV5) Encode() ([]byte, error) {
	var auth xAuthentication
	auth.kind = AuthKindKerberosV5
	auth.data = []byte{}

	return auth.Encode()
}

func (x *xAuthenticationKerberosV5) Decode(_ []byte) error {
	return nil
}

type AuthenticationCleartextPassword struct{}

type xAuthenticationCleartextPassword AuthenticationCleartextPassword

func (x *xAuthenticationCleartextPassword) Encode() ([]byte, error) {
	var auth xAuthentication
	auth.kind = AuthKindCleartextPassword
	auth.data = []byte{}

	return auth.Encode()
}

func (x *xAuthenticationCleartextPassword) Decode(_ []byte) error {
	return nil
}

type AuthenticationMD5Password struct {
	Salt [4]byte
}

type xAuthenticationMD5Password AuthenticationMD5Password

func (x *xAuthenticationMD5Password) Encode() ([]byte, error) {
	var buf bytes.Buffer

	writeBytes(&buf, x.Salt[:])

	var auth xAuthentication
	auth.kind = AuthKindMD5Password
	auth.data = buf.Bytes()

	return auth.Encode()
}

func (x *xAuthenticationMD5Password) Decode(b []byte) error {
	copy(x.Salt[:], b)
	return nil
}

type AuthenticationGSS struct{}

type xAuthenticationGSS AuthenticationGSS

func (x *xAuthenticationGSS) Encode() ([]byte, error) {
	var auth xAuthentication
	auth.kind = AuthKindGSS
	auth.data = []byte{}

	return auth.Encode()
}

func (x *xAuthenticationGSS) Decode(_ []byte) error {
	return nil
}

type AuthenticationGSSContinue struct {
	Data []byte
}

type xAuthenticationGSSContinue AuthenticationGSSContinue

func (x *xAuthenticationGSSContinue) Encode() ([]byte, error) {
	var buf bytes.Buffer

	writeBytes(&buf, x.Data)

	var auth xAuthentication
	auth.kind = AuthKindGSSContinue
	auth.data = buf.Bytes()

	return auth.Encode()
}

func (x *xAuthenticationGSSContinue) Decode(b []byte) error {
	x.Data = make([]byte, len(b))
	copy(x.Data, b)
	return nil
}

type AuthenticationSSPI struct{}

type xAuthenticationSSPI AuthenticationSSPI

func (x *xAuthenticationSSPI) Encode() ([]byte, error) {
	var auth xAuthentication
	auth.kind = AuthKindSSPI
	auth.data = []byte{}

	return auth.Encode()
}

func (x *xAuthenticationSSPI) Decode(_ []byte) error {
	return nil
}

type AuthenticationSASL struct {
	Mechanisms []string
}

type xAuthenticationSASL AuthenticationSASL

func (x *xAuthenticationSASL) Encode() ([]byte, error) {
	var buf bytes.Buffer

	for i := range len(x.Mechanisms) {
		writeString(&buf, x.Mechanisms[i])
	}

	var auth xAuthentication
	auth.kind = AuthKindSASL
	auth.data = buf.Bytes()

	return auth.Encode()
}

func (x *xAuthenticationSASL) Decode(b []byte) error {
	for len(b) > 1 {
		var mechanism string
		bread, err := readString(b, &mechanism)
		if err != nil {
			return err
		}
		b = b[bread:]
		x.Mechanisms = append(x.Mechanisms, mechanism)
	}
	return nil
}

type AuthenticationSASLContinue struct {
	Data []byte
}

type xAuthenticationSASLContinue AuthenticationSASLContinue

func (x *xAuthenticationSASLContinue) Encode() ([]byte, error) {
	var buf bytes.Buffer

	writeBytes(&buf, x.Data)

	var auth xAuthentication
	auth.kind = AuthKindSASLContinue
	auth.data = buf.Bytes()

	return auth.Encode()
}

func (x *xAuthenticationSASLContinue) Decode(b []byte) error {
	x.Data = make([]byte, len(b))
	copy(x.Data, b)
	return nil
}

type AuthenticationSASLFinal struct {
	Data []byte
}

type xAuthenticationSASLFinal AuthenticationSASLFinal

func (x *xAuthenticationSASLFinal) Encode() ([]byte, error) {
	var buf bytes.Buffer

	writeBytes(&buf, x.Data)

	var auth xAuthentication
	auth.kind = AuthKindSASLFinal
	auth.data = buf.Bytes()

	return auth.Encode()
}

func (x *xAuthenticationSASLFinal) Decode(b []byte) error {
	x.Data = make([]byte, len(b))
	copy(x.Data, b)
	return nil
}

type BackendKeyData struct {
	ProcessID int32
	SecretKey []byte
}

type xBackendKeyData BackendKeyData

func (x *xBackendKeyData) Encode() ([]byte, error) {
	var buf bytes.Buffer

	writeInt32(&buf, x.ProcessID)
	writeBytes(&buf, x.SecretKey)

	var msg xMessage
	msg.kind = KindKeyData
	msg.data = buf.Bytes()

	return msg.Encode()
}

func (x *xBackendKeyData) Decode(b []byte) error {
	bread, err := readInt32(b, &x.ProcessID)
	if err != nil {
		return err
	}
	b = b[bread:]

	if len(b) < 4 {
		return ErrValueUnderflow
	}

	if len(b) > 256 {
		return ErrValueOverflow
	}
	x.SecretKey = make([]byte, len(b))
	copy(x.SecretKey, b)
	return nil
}

type BindComplete struct{}

type xBindComplete BindComplete

func (x *xBindComplete) Encode() ([]byte, error) {
	var msg xMessage
	msg.kind = KindBindComplete
	msg.data = []byte{}

	return msg.Encode()
}

func (x *xBindComplete) Decode(_ []byte) error {
	return nil
}

type CloseComplete struct{}

type xCloseComplete CloseComplete

func (x *xCloseComplete) Encode() ([]byte, error) {
	var msg xMessage
	msg.kind = KindCloseComplete
	msg.data = []byte{}

	return msg.Encode()
}

func (x *xCloseComplete) Decode(_ []byte) error {
	return nil
}

type CommandComplete struct {
	Tag string
}

type xCommandComplete CommandComplete

func (x *xCommandComplete) Encode() ([]byte, error) {
	var buf bytes.Buffer

	writeString(&buf, x.Tag)

	var msg xMessage
	msg.kind = KindCommandComplete
	msg.data = buf.Bytes()

	return msg.Encode()
}

func (x *xCommandComplete) Decode(b []byte) error {
	_, err := readString(b, &x.Tag)
	return err
}

type CopyData struct {
	Data []byte
}

type xCopyData CopyData

func (x *xCopyData) Encode() ([]byte, error) {
	var buf bytes.Buffer

	writeBytes(&buf, x.Data)

	var msg xMessage
	msg.kind = KindCopyData
	msg.data = buf.Bytes()

	return msg.Encode()
}

func (x *xCopyData) Decode(b []byte) error {
	x.Data = make([]byte, len(b))
	copy(x.Data, b)
	return nil
}

type CopyDone struct{}

type xCopyDone CopyDone

func (x *xCopyDone) Encode() ([]byte, error) {
	var msg xMessage
	msg.kind = KindCopyDone
	msg.data = []byte{}

	return msg.Encode()
}

func (x *xCopyDone) Decode(_ []byte) error {
	return nil
}

type CopyInResponse struct {
	Format  Format
	Columns []Format
}

type xCopyInResponse CopyInResponse

func (x *xCopyInResponse) Encode() ([]byte, error) {
	var buf bytes.Buffer

	writeFormat(&buf, x.Format)
	writeInt16(&buf, int16(len(x.Columns)))
	for _, f := range x.Columns {
		writeFormat(&buf, f)
	}

	var msg xMessage
	msg.kind = KindCopyInResponse
	msg.data = buf.Bytes()

	return msg.Encode()
}

func (x *xCopyInResponse) Decode(b []byte) error {
	var format int8
	bread, err := readInt8(b, &format)
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

	x.Format, err = ParseFormat(int16(format))
	if err != nil {
		return err
	}

	x.Columns = make([]Format, int(columns))
	for i := range columns {
		var format int16
		bread, err = readInt16(b, &format)
		if err != nil {
			return err
		}
		b = b[bread:]
		x.Columns[i], err = ParseFormat(format)
		if err != nil {
			return err
		}
	}
	return nil
}

type CopyOutResponse struct {
	Format  Format
	Columns []Format
}

type xCopyOutResponse CopyOutResponse

func (x *xCopyOutResponse) Encode() ([]byte, error) {
	var buf bytes.Buffer

	writeFormat(&buf, x.Format)
	writeInt16(&buf, int16(len(x.Columns)))
	for _, f := range x.Columns {
		writeFormat(&buf, f)
	}

	var msg xMessage
	msg.kind = KindCopyOutResponse
	msg.data = buf.Bytes()

	return msg.Encode()
}

func (x *xCopyOutResponse) Decode(b []byte) error {
	var format int8
	bread, err := readInt8(b, &format)
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

	x.Format, err = ParseFormat(int16(format))
	if err != nil {
		return err
	}

	x.Columns = make([]Format, int(columns))
	for i := range columns {
		var format int16
		bread, err = readInt16(b, &format)
		if err != nil {
			return err
		}
		b = b[bread:]
		x.Columns[i], err = ParseFormat(format)
		if err != nil {
			return err
		}
	}
	return nil
}

type CopyBothResponse struct {
	Format  Format
	Columns []Format
}

type xCopyBothResponse CopyBothResponse

func (x *xCopyBothResponse) Encode() ([]byte, error) {
	var buf bytes.Buffer

	writeFormat(&buf, x.Format)
	writeInt16(&buf, int16(len(x.Columns)))
	for _, f := range x.Columns {
		writeFormat(&buf, f)
	}

	var msg xMessage
	msg.kind = KindCopyBothResponse
	msg.data = buf.Bytes()

	return msg.Encode()
}

func (x *xCopyBothResponse) Decode(b []byte) error {
	var format int8
	bread, err := readInt8(b, &format)
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

	x.Format, err = ParseFormat(int16(format))
	if err != nil {
		return err
	}

	x.Columns = make([]Format, int(columns))
	for i := range columns {
		var format int16
		bread, err = readInt16(b, &format)
		if err != nil {
			return err
		}
		b = b[bread:]
		x.Columns[i], err = ParseFormat(format)
		if err != nil {
			return err
		}
	}
	return nil
}

type DataRow struct {
	// First dimention is columns (can have 0 elements).
	// Second dimension is value data (can have 0 elements
	// or be nil).
	Columns [][]byte
}

type xDataRow DataRow

func (x *xDataRow) Encode() ([]byte, error) {
	var buf bytes.Buffer

	writeInt16(&buf, int16(len(x.Columns)))
	for _, column := range x.Columns {
		writeInt32(&buf, int32(len(column)))
		writeBytes(&buf, column)
	}

	var msg xMessage
	msg.kind = KindDataRow
	msg.data = buf.Bytes()

	return msg.Encode()
}

func (x *xDataRow) Decode(b []byte) error {
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

type EmptyQueryResponse struct{}

type xEmptyQueryResponse EmptyQueryResponse

func (x *xEmptyQueryResponse) Encode() ([]byte, error) {
	var msg xMessage
	msg.kind = KindEmptyQueryResponse
	msg.data = []byte{}

	return msg.Encode()
}

func (x *xEmptyQueryResponse) Decode(_ []byte) error {
	return nil
}

type ErrorResponse struct {
	Fields []Field
	Values []string
}

type xErrorResponse ErrorResponse

func (x *xErrorResponse) Encode() ([]byte, error) {
	var buf bytes.Buffer

	for i := range len(x.Fields) {
		writeField(&buf, x.Fields[i])
		writeString(&buf, x.Values[i])
	}

	var msg xMessage
	msg.kind = KindErrorResponse
	msg.data = buf.Bytes()

	return msg.Encode()
}

func (x *xErrorResponse) Decode(b []byte) error {
	var f byte
	bread, err := readByte(b, &f)
	if err != nil {
		return err
	}
	b = b[bread:]

	for f != 0 {
		field, err := ParseField(f)
		if err != nil {
			return err
		}
		x.Fields = append(x.Fields, Field(field))
		var value string
		bread, err = readString(b, &value)
		if err != nil {
			return err
		}
		b = b[bread:]
		x.Values = append(x.Values, value)
		bread, err = readByte(b, &f)
		if err != nil {
			return err
		}
		b = b[bread:]
	}
	return nil
}

type FunctionCallResponse struct {
	// Can be zero length or nil.
	Result []byte
}

type xFunctionCallResponse FunctionCallResponse

func (x *xFunctionCallResponse) Encode() ([]byte, error) {
	var buf bytes.Buffer

	writeBytes(&buf, x.Result)

	var msg xMessage
	msg.kind = KindFunctionCallResponse
	msg.data = buf.Bytes()

	return msg.Encode()
}

func (x *xFunctionCallResponse) Decode(b []byte) error {
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

type NegotiateProtocolVersion struct {
	MinorVersionSupported int32
	UnrecognizedOptions   []string
}

type xNegotiateProtocolVersion NegotiateProtocolVersion

func (x *xNegotiateProtocolVersion) Decode(b []byte) error {
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

type NoData struct{}

type xNoData NoData

func (x *xNoData) Decode(_ []byte) error {
	return nil
}

type NoticeResponse struct {
	Fields []Field
	Values []string
}

type xNoticeResponse NoticeResponse

func (x *xNoticeResponse) Decode(b []byte) error {
	var f byte
	bread, err := readByte(b, &f)
	if err != nil {
		return err
	}
	b = b[bread:]

	for f != 0 {
		field, err := ParseField(f)
		if err != nil {
			return err
		}
		x.Fields = append(x.Fields, Field(field))
		var value string
		bread, err = readString(b, &value)
		if err != nil {
			return err
		}
		b = b[bread:]
		x.Values = append(x.Values, value)
		bread, err = readByte(b, &f)
		if err != nil {
			return err
		}
		b = b[bread:]
	}
	return nil
}

type NotificationResponse struct {
	ProcessID int32
	Channel   string
	Payload   string
}

type xNotificationResponse NotificationResponse

func (x *xNotificationResponse) Decode(b []byte) error {
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

	bread, err = readString(b, &x.Payload)
	if err != nil {
		return err
	}
	return nil
}

type ParameterDescription struct {
	Parameters []int32
}

type xParameterDescription ParameterDescription

func (x *xParameterDescription) Decode(b []byte) error {
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

type ParameterStatus struct {
	Name  string
	Value string
}

type xParameterStatus ParameterStatus

func (x *xParameterStatus) Decode(b []byte) error {
	bread, err := readString(b, &x.Name)
	if err != nil {
		return err
	}
	b = b[bread:]

	bread, err = readString(b, &x.Value)
	if err != nil {
		return err
	}
	return nil
}

type ParseComplete struct{}

type xParseComplete ParseComplete

func (x *xParseComplete) Decode(_ []byte) error {
	return nil
}

type PortalSuspended struct{}

type xPortalSuspended PortalSuspended

func (x *xPortalSuspended) Decode(_ []byte) error {
	return nil
}

type ReadyForQuery struct {
	TxStatus TxStatus
}

type xReadyForQuery ReadyForQuery

func (x *xReadyForQuery) Decode(b []byte) error {
	var status byte
	_, err := readByte(b, &status)
	if err != nil {
		return err
	}
	x.TxStatus, err = ParseTxStatus(status)
	if err != nil {
		return err
	}
	return nil
}

type RowDescription struct {
	Names     []string
	Tables    []int32
	Columns   []int16
	DataTypes []int32
	Sizes     []int16
	Modifiers []int32
	Formats   []Format
}

type xRowDescription RowDescription

func (x *xRowDescription) Decode(b []byte) error {
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
	x.Formats = make([]Format, length)

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

		var format int16
		bread, err = readInt16(b, &format)
		if err != nil {
			return err
		}
		b = b[bread:]

		x.Formats[i], err = ParseFormat(format)
		if err != nil {
			return err
		}
	}
	return nil
}

type Unknown struct{}

type xMessage struct {
	kind Kind
	data []byte
}

func (m *xMessage) Encode() ([]byte, error) {
	var buf bytes.Buffer

	writeKind(&buf, m.kind)
	writeInt32(&buf, int32(len(m.data)))
	writeBytes(&buf, m.data)

	return buf.Bytes(), nil
}

func ReadMessage(r io.Reader, m *xMessage) error {
	var byteKind [1]byte
	var byteLength [4]byte

	bread, err := r.Read(byteKind[:])
	if err != nil {
		if err == io.EOF {
			return io.ErrUnexpectedEOF
		}
		return err
	}

	if bread != 1 {
		return io.ErrUnexpectedEOF
	}

	bread, err = r.Read(byteLength[:])
	if err != nil {
		if err == io.EOF {
			return io.ErrUnexpectedEOF
		}
		return err
	}

	if bread != 4 {
		return io.ErrUnexpectedEOF
	}

	m.kind, err = ParseKind(byteKind[0])
	if err != nil {
		return err
	}
	length := int32(binary.BigEndian.Uint32(byteLength[:])) - 4

	byteBody := make([]byte, int(length))

	bread, err = r.Read(byteBody)
	if err != nil {
		if err == io.EOF {
			return io.ErrUnexpectedEOF
		}
		return err
	}

	if bread != int(length) {
		return io.ErrUnexpectedEOF
	}
	m.data = byteBody

	return nil
}

func (m *xMessage) Parse() (any, error) {
	switch m.kind {
	case KindAuthentication:
		var x xAuthentication
		err := x.Decode(m.data)
		if err != nil {
			return nil, err
		}
		return x.Parse()
	case KindKeyData:
		var x xBackendKeyData
		err := x.Decode(m.data)
		return BackendKeyData(x), err
	case KindBindComplete:
		var x xBindComplete
		err := x.Decode(m.data)
		return BindComplete(x), err
	case KindCloseComplete:
		var x xCloseComplete
		err := x.Decode(m.data)
		return CloseComplete(x), err
	case KindCommandComplete:
		var x xCommandComplete
		err := x.Decode(m.data)
		return CommandComplete(x), err
	case KindCopyData:
		var x xCopyData
		err := x.Decode(m.data)
		return CopyData(x), err
	case KindCopyDone:
		var x xCopyDone
		err := x.Decode(m.data)
		return CopyDone(x), err
	case KindCopyInResponse:
		var x xCopyInResponse
		err := x.Decode(m.data)
		return CopyInResponse(x), err
	case KindCopyOutResponse:
		var x xCopyOutResponse
		err := x.Decode(m.data)
		return CopyOutResponse(x), err
	case KindCopyBothResponse:
		var x xCopyBothResponse
		err := x.Decode(m.data)
		return CopyBothResponse(x), err
	case KindDataRow:
		var x xDataRow
		err := x.Decode(m.data)
		return DataRow(x), err
	case KindEmptyQueryResponse:
		var x xEmptyQueryResponse
		err := x.Decode(m.data)
		return EmptyQueryResponse(x), err
	case KindErrorResponse:
		var x xErrorResponse
		err := x.Decode(m.data)
		return ErrorResponse(x), err
	case KindFunctionCallResponse:
		var x xFunctionCallResponse
		err := x.Decode(m.data)
		return FunctionCallResponse(x), err
	case KindNegotiateProtocolVersion:
		var x xNegotiateProtocolVersion
		err := x.Decode(m.data)
		return NegotiateProtocolVersion(x), err
	case KindNoData:
		var x xNoData
		err := x.Decode(m.data)
		return NoData(x), err
	case KindNoticeResponse:
		var x xNoticeResponse
		err := x.Decode(m.data)
		return NoticeResponse(x), err
	case KindNotificationResponse:
		var x xNotificationResponse
		err := x.Decode(m.data)
		return NotificationResponse(x), err
	case KindParameterDescription:
		var x xParameterDescription
		err := x.Decode(m.data)
		return ParameterDescription(x), err
	case KindParameterStatus:
		var x xParameterStatus
		err := x.Decode(m.data)
		return ParameterStatus(x), err
	case KindParseComplete:
		var x xParseComplete
		err := x.Decode(m.data)
		return ParseComplete(x), err
	case KindPortalSuspended:
		var x xPortalSuspended
		err := x.Decode(m.data)
		return PortalSuspended(x), err
	case KindReadyForQuery:
		var x xReadyForQuery
		err := x.Decode(m.data)
		return ReadyForQuery(x), err
	case KindRowDescription:
		var x xRowDescription
		err := x.Decode(m.data)
		return RowDescription(x), err
	default:
		return Unknown{}, nil
	}
}

func readAuthKind(b []byte, v *AuthKind) (int, error) {
	var i int32
	bread, err := readInt32(b, &i)
	if err != nil {
		return bread, err
	}
	*v, err = ParseAuthKind(i)
	return bread, err
}

func readByte(b []byte, v *byte) (int, error) {
	if len(b) < 1 {
		return 0, ErrValueUnderflow
	}
	*v = b[0]
	return 1, nil
}

func readInt8(b []byte, i *int8) (int, error) {
	var v byte
	bread, err := readByte(b, &v)
	if err != nil {
		return bread, err
	}
	*i = int8(v)
	return bread, nil
}

func readInt16(b []byte, i *int16) (int, error) {
	if len(b) < 2 {
		return 0, ErrValueUnderflow
	}
	*i = int16(binary.BigEndian.Uint16(b[:2]))
	return 2, nil
}

func readInt32(b []byte, i *int32) (int, error) {
	if len(b) < 4 {
		return 0, ErrValueUnderflow
	}
	*i = int32(binary.BigEndian.Uint32(b[:4]))
	return 4, nil
}

func readString(b []byte, s *string) (int, error) {
	ndx := bytes.IndexByte(b, 0)
	if ndx > -1 {
		*s = string(b[:ndx])
		return ndx + 1, nil
	}
	return 0, ErrValueUnderflow
}

func writeField(buf *bytes.Buffer, f Field) {
	_ = buf.WriteByte(byte(f))
}

func writeFormat(buf *bytes.Buffer, f Format) {
	writeInt16(buf, int16(f))
}

func writeAuthKind(buf *bytes.Buffer, k AuthKind) {
	writeInt32(buf, int32(k))
}

func writeKind(buf *bytes.Buffer, k Kind) {
	_ = buf.WriteByte(byte(k))
}

func writeTxStatus(buf *bytes.Buffer, s TxStatus) {
	_ = buf.WriteByte(byte(s))
}

func writeInt8(buf *bytes.Buffer, i byte) {
	_ = buf.WriteByte(i)
}

func writeInt16(buf *bytes.Buffer, i int16) {
	bytes := make([]byte, 2)
	binary.BigEndian.PutUint16(bytes, uint16(i))

	_, _ = buf.Write(bytes)
}

func writeInt32(buf *bytes.Buffer, i int32) {
	bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(bytes, uint32(i))

	_, _ = buf.Write(bytes)
}

func writeString(buf *bytes.Buffer, s string) {
	bytes := []byte(s)
	bytes = append(bytes, 0)

	_, _ = buf.Write(bytes)
}

func writeBytes(buf *bytes.Buffer, b []byte) {
	_, _ = buf.Write(b)
}

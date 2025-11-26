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

const (
	msgKindAuthentication           byte = 'R'
	msgKindKeyData                  byte = 'K'
	msgKindBindComplete             byte = '2'
	msgKindCloseComplete            byte = '3'
	msgKindCommandComplete          byte = 'C'
	msgKindCopyData                 byte = 'd'
	msgKindCopyDone                 byte = 'c'
	msgKindCopyInResponse           byte = 'G'
	msgKindCopyOutResponse          byte = 'H'
	msgKindCopyBothResponse         byte = 'W'
	msgKindDataRow                  byte = 'D'
	msgKindEmptyQueryResponse       byte = 'I'
	msgKindErrorResponse            byte = 'E'
	msgKindFunctionCallResponse     byte = 'V'
	msgKindNegotiateProtocolVersion byte = 'v'
	msgKindNoData                   byte = 'n'
	msgKindNoticeResponse           byte = 'N'
	msgKindNotificationResponse     byte = 'A'
	msgKindParameterDescription     byte = 't'
	msgKindParameterStatus          byte = 'S'
	msgKindParseComplete            byte = '1'
	msgKindPortalSuspended          byte = 's'
	msgKindReadyForQuery            byte = 'Z'
	msgKindRowDescription           byte = 'T'
)

const (
	authKindOk                int32 = 0
	authKindKerberosV5        int32 = 2
	authKindCleartextPassword int32 = 3
	authKindMD5Password       int32 = 5
	authKindGSS               int32 = 7
	authKindGSSContinue       int32 = 8
	authKindSSPI              int32 = 9
	authKindSASL              int32 = 10
	authKindSASLContinue      int32 = 11
	authKindSASLFinal         int32 = 12
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

func Read(r io.Reader) (any, error) {
	var header [5]byte

	_, err := io.ReadFull(r, header[:])
	if err != nil {
		if err == io.EOF {
			return nil, io.ErrUnexpectedEOF
		}
		return nil, err
	}

	kind := header[0]

	var length int32
	_, err = readInt32(header[1:], &length)
	if err != nil {
		return nil, err
	}

	data := make([]byte, length-4)
	_, err = io.ReadFull(r, data)
	if err != nil {
		if err == io.EOF {
			return nil, io.ErrUnexpectedEOF
		}
		return nil, err
	}

	return parseMessage(kind, data)
}

func Write(w io.Writer, m any) error {
	var enc encoder

	switch v := m.(type) {
	case *AuthenticationOk:
		enc = (*xAuthenticationOk)(v)
	case *AuthenticationKerberosV5:
		enc = (*xAuthenticationKerberosV5)(v)
	case *AuthenticationCleartextPassword:
		enc = (*xAuthenticationCleartextPassword)(v)
	case *AuthenticationMD5Password:
		enc = (*xAuthenticationMD5Password)(v)
	case *AuthenticationGSS:
		enc = (*xAuthenticationGSS)(v)
	case *AuthenticationGSSContinue:
		enc = (*xAuthenticationGSSContinue)(v)
	case *AuthenticationSSPI:
		enc = (*xAuthenticationSSPI)(v)
	case *AuthenticationSASL:
		enc = (*xAuthenticationSASL)(v)
	case *AuthenticationSASLContinue:
		enc = (*xAuthenticationSASLContinue)(v)
	case *AuthenticationSASLFinal:
		enc = (*xAuthenticationSASLFinal)(v)
	case *BackendKeyData:
		enc = (*xBackendKeyData)(v)
	case *BindComplete:
		enc = (*xBindComplete)(v)
	case *CloseComplete:
		enc = (*xCloseComplete)(v)
	case *CommandComplete:
		enc = (*xCommandComplete)(v)
	case *CopyData:
		enc = (*xCopyData)(v)
	case *CopyDone:
		enc = (*xCopyDone)(v)
	case *CopyInResponse:
		enc = (*xCopyInResponse)(v)
	case *CopyOutResponse:
		enc = (*xCopyOutResponse)(v)
	case *CopyBothResponse:
		enc = (*xCopyBothResponse)(v)
	case *DataRow:
		enc = (*xDataRow)(v)
	case *EmptyQueryResponse:
		enc = (*xEmptyQueryResponse)(v)
	case *ErrorResponse:
		enc = (*xErrorResponse)(v)
	case *FunctionCallResponse:
		enc = (*xFunctionCallResponse)(v)
	case *NegotiateProtocolVersion:
		enc = (*xNegotiateProtocolVersion)(v)
	case *NoData:
		enc = (*xNoData)(v)
	case *NoticeResponse:
		enc = (*xNoticeResponse)(v)
	case *NotificationResponse:
		enc = (*xNotificationResponse)(v)
	case *ParameterDescription:
		enc = (*xParameterDescription)(v)
	case *ParameterStatus:
		enc = (*xParameterStatus)(v)
	case *ParseComplete:
		enc = (*xParseComplete)(v)
	case *PortalSuspended:
		enc = (*xPortalSuspended)(v)
	case *ReadyForQuery:
		enc = (*xReadyForQuery)(v)
	case *RowDescription:
		enc = (*xRowDescription)(v)
	default:
		return ErrInvalidValue
	}

	return enc.Encode(w)
}

type encoder interface {
	Encode(io.Writer) error
}

func parseAuthentication(kind int32, data []byte) (any, error) {
	switch kind {
	case authKindOk:
		var x xAuthenticationOk
		err := x.Decode(data)
		return AuthenticationOk(x), err
	case authKindKerberosV5:
		var x xAuthenticationKerberosV5
		err := x.Decode(data)
		return AuthenticationKerberosV5(x), err
	case authKindCleartextPassword:
		var x xAuthenticationCleartextPassword
		err := x.Decode(data)
		return AuthenticationCleartextPassword(x), err
	case authKindMD5Password:
		var x xAuthenticationMD5Password
		err := x.Decode(data)
		return AuthenticationMD5Password(x), err
	case authKindGSS:
		var x xAuthenticationGSS
		err := x.Decode(data)
		return AuthenticationGSS(x), err
	case authKindGSSContinue:
		var x xAuthenticationGSSContinue
		err := x.Decode(data)
		return AuthenticationGSSContinue(x), err
	case authKindSSPI:
		var x xAuthenticationSSPI
		err := x.Decode(data)
		return AuthenticationSSPI(x), err
	case authKindSASL:
		var x xAuthenticationSASL
		err := x.Decode(data)
		return AuthenticationSASL(x), err
	case authKindSASLContinue:
		var x xAuthenticationSASLContinue
		err := x.Decode(data)
		return AuthenticationSASLContinue(x), err
	case authKindSASLFinal:
		var x xAuthenticationSASLFinal
		err := x.Decode(data)
		return AuthenticationSASLFinal(x), err
	default:
		return Unknown{}, nil
	}
}

type AuthenticationOk struct{}

type xAuthenticationOk AuthenticationOk

func (x *xAuthenticationOk) Encode(w io.Writer) error {
	var buf bytes.Buffer
	writeInt32(&buf, authKindOk)
	return writeMessage(w, msgKindAuthentication, buf.Bytes())
}

func (x *xAuthenticationOk) Decode(_ []byte) error {
	return nil
}

type AuthenticationKerberosV5 struct{}

type xAuthenticationKerberosV5 AuthenticationKerberosV5

func (x *xAuthenticationKerberosV5) Encode(w io.Writer) error {
	var buf bytes.Buffer
	writeInt32(&buf, authKindKerberosV5)
	return writeMessage(w, msgKindAuthentication, buf.Bytes())
}

func (x *xAuthenticationKerberosV5) Decode(_ []byte) error {
	return nil
}

type AuthenticationCleartextPassword struct{}

type xAuthenticationCleartextPassword AuthenticationCleartextPassword

func (x *xAuthenticationCleartextPassword) Encode(w io.Writer) error {
	var buf bytes.Buffer
	writeInt32(&buf, authKindCleartextPassword)
	return writeMessage(w, msgKindAuthentication, buf.Bytes())
}

func (x *xAuthenticationCleartextPassword) Decode(_ []byte) error {
	return nil
}

type AuthenticationMD5Password struct {
	Salt [4]byte
}

type xAuthenticationMD5Password AuthenticationMD5Password

func (x *xAuthenticationMD5Password) Encode(w io.Writer) error {
	var buf bytes.Buffer
	writeInt32(&buf, authKindMD5Password)
	writeBytes(&buf, x.Salt[:])
	return writeMessage(w, msgKindAuthentication, buf.Bytes())
}

func (x *xAuthenticationMD5Password) Decode(b []byte) error {
	copy(x.Salt[:], b)
	return nil
}

type AuthenticationGSS struct{}

type xAuthenticationGSS AuthenticationGSS

func (x *xAuthenticationGSS) Encode(w io.Writer) error {
	var buf bytes.Buffer
	writeInt32(&buf, authKindGSS)
	return writeMessage(w, msgKindAuthentication, buf.Bytes())
}

func (x *xAuthenticationGSS) Decode(_ []byte) error {
	return nil
}

type AuthenticationGSSContinue struct {
	Data []byte
}

type xAuthenticationGSSContinue AuthenticationGSSContinue

func (x *xAuthenticationGSSContinue) Encode(w io.Writer) error {
	var buf bytes.Buffer
	writeInt32(&buf, authKindGSSContinue)
	writeBytes(&buf, x.Data)
	return writeMessage(w, msgKindAuthentication, buf.Bytes())
}

func (x *xAuthenticationGSSContinue) Decode(b []byte) error {
	x.Data = make([]byte, len(b))
	copy(x.Data, b)
	return nil
}

type AuthenticationSSPI struct{}

type xAuthenticationSSPI AuthenticationSSPI

func (x *xAuthenticationSSPI) Encode(w io.Writer) error {
	var buf bytes.Buffer
	writeInt32(&buf, authKindSSPI)
	return writeMessage(w, msgKindAuthentication, buf.Bytes())
}

func (x *xAuthenticationSSPI) Decode(_ []byte) error {
	return nil
}

type AuthenticationSASL struct {
	Mechanisms []string
}

type xAuthenticationSASL AuthenticationSASL

func (x *xAuthenticationSASL) Encode(w io.Writer) error {
	var buf bytes.Buffer
	writeInt32(&buf, authKindSASL)
	for i := range len(x.Mechanisms) {
		writeString(&buf, x.Mechanisms[i])
	}
	return writeMessage(w, msgKindAuthentication, buf.Bytes())
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

func (x *xAuthenticationSASLContinue) Encode(w io.Writer) error {
	var buf bytes.Buffer
	writeInt32(&buf, authKindSASLContinue)
	writeBytes(&buf, x.Data)
	return writeMessage(w, msgKindAuthentication, buf.Bytes())
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

func (x *xAuthenticationSASLFinal) Encode(w io.Writer) error {
	var buf bytes.Buffer
	writeInt32(&buf, authKindSASLFinal)
	writeBytes(&buf, x.Data)
	return writeMessage(w, msgKindAuthentication, buf.Bytes())
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

func (x *xBackendKeyData) Encode(w io.Writer) error {
	var buf bytes.Buffer
	writeInt32(&buf, x.ProcessID)
	writeBytes(&buf, x.SecretKey)
	return writeMessage(w, msgKindKeyData, buf.Bytes())
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

func (x *xBindComplete) Encode(w io.Writer) error {
	return writeMessage(w, msgKindBindComplete, []byte{})
}

func (x *xBindComplete) Decode(_ []byte) error {
	return nil
}

type CloseComplete struct{}

type xCloseComplete CloseComplete

func (x *xCloseComplete) Encode(w io.Writer) error {
	return writeMessage(w, msgKindCloseComplete, []byte{})
}

func (x *xCloseComplete) Decode(_ []byte) error {
	return nil
}

type CommandComplete struct {
	Tag string
}

type xCommandComplete CommandComplete

func (x *xCommandComplete) Encode(w io.Writer) error {
	var buf bytes.Buffer
	writeString(&buf, x.Tag)
	return writeMessage(w, msgKindCommandComplete, buf.Bytes())
}

func (x *xCommandComplete) Decode(b []byte) error {
	_, err := readString(b, &x.Tag)
	return err
}

type CopyData struct {
	Data []byte
}

type xCopyData CopyData

func (x *xCopyData) Encode(w io.Writer) error {
	var buf bytes.Buffer
	writeBytes(&buf, x.Data)
	return writeMessage(w, msgKindCopyData, buf.Bytes())
}

func (x *xCopyData) Decode(b []byte) error {
	x.Data = make([]byte, len(b))
	copy(x.Data, b)
	return nil
}

type CopyDone struct{}

type xCopyDone CopyDone

func (x *xCopyDone) Encode(w io.Writer) error {
	return writeMessage(w, msgKindCopyDone, []byte{})
}

func (x *xCopyDone) Decode(_ []byte) error {
	return nil
}

type CopyInResponse struct {
	Format  int8
	Columns []int16
}

type xCopyInResponse CopyInResponse

func (x *xCopyInResponse) Encode(w io.Writer) error {
	var buf bytes.Buffer
	writeInt8(&buf, x.Format)
	writeInt16(&buf, int16(len(x.Columns)))
	for _, f := range x.Columns {
		writeInt16(&buf, f)
	}
	return writeMessage(w, msgKindCopyInResponse, buf.Bytes())
}

func (x *xCopyInResponse) Decode(b []byte) error {
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

type CopyOutResponse struct {
	Format  int8
	Columns []int16
}

type xCopyOutResponse CopyOutResponse

func (x *xCopyOutResponse) Encode(w io.Writer) error {
	var buf bytes.Buffer
	writeInt8(&buf, x.Format)
	writeInt16(&buf, int16(len(x.Columns)))
	for _, f := range x.Columns {
		writeInt16(&buf, f)
	}
	return writeMessage(w, msgKindCopyOutResponse, buf.Bytes())
}

func (x *xCopyOutResponse) Decode(b []byte) error {
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

type CopyBothResponse struct {
	Format  int8
	Columns []int16
}

type xCopyBothResponse CopyBothResponse

func (x *xCopyBothResponse) Encode(w io.Writer) error {
	var buf bytes.Buffer
	writeInt8(&buf, x.Format)
	writeInt16(&buf, int16(len(x.Columns)))
	for _, f := range x.Columns {
		writeInt16(&buf, f)
	}
	return writeMessage(w, msgKindCopyBothResponse, buf.Bytes())
}

func (x *xCopyBothResponse) Decode(b []byte) error {
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

type DataRow struct {
	// First dimention is columns (can have 0 elements).
	// Second dimension is value data (can have 0 elements
	// or be nil).
	Columns [][]byte
}

type xDataRow DataRow

func (x *xDataRow) Encode(w io.Writer) error {
	var buf bytes.Buffer
	writeInt16(&buf, int16(len(x.Columns)))
	for _, column := range x.Columns {
		writeInt32(&buf, int32(len(column)))
		writeBytes(&buf, column)
	}
	return writeMessage(w, msgKindDataRow, buf.Bytes())
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

func (x *xEmptyQueryResponse) Encode(w io.Writer) error {
	return writeMessage(w, msgKindEmptyQueryResponse, []byte{})
}

func (x *xEmptyQueryResponse) Decode(_ []byte) error {
	return nil
}

type ErrorResponse struct {
	Fields []byte
	Values []string
}

type xErrorResponse ErrorResponse

func (x *xErrorResponse) Encode(w io.Writer) error {
	var buf bytes.Buffer
	for i := range len(x.Fields) {
		writeByte(&buf, x.Fields[i])
		writeString(&buf, x.Values[i])
	}
	writeByte(&buf, 0)
	return writeMessage(w, msgKindErrorResponse, buf.Bytes())
}

func (x *xErrorResponse) Decode(b []byte) error {
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

type FunctionCallResponse struct {
	// Can be zero length or nil.
	Result []byte
}

type xFunctionCallResponse FunctionCallResponse

func (x *xFunctionCallResponse) Encode(w io.Writer) error {
	var buf bytes.Buffer
	writeBytes(&buf, x.Result)
	return writeMessage(w, msgKindFunctionCallResponse, buf.Bytes())
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

func (x *xNegotiateProtocolVersion) Encode(w io.Writer) error {
	var buf bytes.Buffer
	writeInt32(&buf, x.MinorVersionSupported)
	writeInt32(&buf, int32(len(x.UnrecognizedOptions)))
	for _, option := range x.UnrecognizedOptions {
		writeString(&buf, option)
	}
	return writeMessage(w, msgKindNegotiateProtocolVersion, buf.Bytes())
}

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

func (x *xNoData) Encode(w io.Writer) error {
	return writeMessage(w, msgKindNoData, []byte{})
}

func (x *xNoData) Decode(_ []byte) error {
	return nil
}

type NoticeResponse struct {
	Fields []byte
	Values []string
}

type xNoticeResponse NoticeResponse

func (x *xNoticeResponse) Encode(w io.Writer) error {
	var buf bytes.Buffer
	for i := range len(x.Fields) {
		writeByte(&buf, x.Fields[i])
		writeString(&buf, x.Values[i])
	}
	writeByte(&buf, 0)
	return writeMessage(w, msgKindNoticeResponse, buf.Bytes())
}

func (x *xNoticeResponse) Decode(b []byte) error {
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

type NotificationResponse struct {
	ProcessID int32
	Channel   string
	Payload   string
}

type xNotificationResponse NotificationResponse

func (x *xNotificationResponse) Encode(w io.Writer) error {
	var buf bytes.Buffer
	writeInt32(&buf, x.ProcessID)
	writeString(&buf, x.Channel)
	writeString(&buf, x.Payload)
	return writeMessage(w, msgKindNotificationResponse, buf.Bytes())
}

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

func (x *xParameterDescription) Encode(w io.Writer) error {
	var buf bytes.Buffer
	writeInt16(&buf, int16(len(x.Parameters)))
	for _, param := range x.Parameters {
		writeInt32(&buf, param)
	}
	return writeMessage(w, msgKindParameterDescription, buf.Bytes())
}

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

func (x *xParameterStatus) Encode(w io.Writer) error {
	var buf bytes.Buffer
	writeString(&buf, x.Name)
	writeString(&buf, x.Value)
	return writeMessage(w, msgKindParameterStatus, buf.Bytes())
}

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

func (x *xParseComplete) Encode(w io.Writer) error {
	return writeMessage(w, msgKindParseComplete, []byte{})
}

func (x *xParseComplete) Decode(_ []byte) error {
	return nil
}

type PortalSuspended struct{}

type xPortalSuspended PortalSuspended

func (x *xPortalSuspended) Encode(w io.Writer) error {
	return writeMessage(w, msgKindPortalSuspended, []byte{})
}

func (x *xPortalSuspended) Decode(_ []byte) error {
	return nil
}

type ReadyForQuery struct {
	TxStatus byte
}

type xReadyForQuery ReadyForQuery

func (x *xReadyForQuery) Encode(w io.Writer) error {
	var buf bytes.Buffer
	writeByte(&buf, x.TxStatus)
	return writeMessage(w, msgKindReadyForQuery, buf.Bytes())
}

func (x *xReadyForQuery) Decode(b []byte) error {
	_, err := readByte(b, &x.TxStatus)
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
	Formats   []int16
}

type xRowDescription RowDescription

func (x *xRowDescription) Encode(w io.Writer) error {
	var buf bytes.Buffer
	writeInt16(&buf, int16(len(x.Names)))
	for i := range len(x.Names) {
		writeString(&buf, x.Names[i])
		writeInt32(&buf, x.Tables[i])
		writeInt16(&buf, x.Columns[i])
		writeInt32(&buf, x.DataTypes[i])
		writeInt16(&buf, x.Sizes[i])
		writeInt32(&buf, x.Modifiers[i])
		writeInt16(&buf, x.Formats[i])
	}
	return writeMessage(w, msgKindRowDescription, buf.Bytes())
}

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

type Unknown struct{}

func parseMessage(kind byte, data []byte) (any, error) {
	switch kind {
	case msgKindAuthentication:
		var k int32
		bread, err := readInt32(data, &k)
		if err != nil {
			return nil, err
		}
		d := data[bread:]
		return parseAuthentication(k, d)
	case msgKindKeyData:
		var x xBackendKeyData
		err := x.Decode(data)
		return BackendKeyData(x), err
	case msgKindBindComplete:
		var x xBindComplete
		err := x.Decode(data)
		return BindComplete(x), err
	case msgKindCloseComplete:
		var x xCloseComplete
		err := x.Decode(data)
		return CloseComplete(x), err
	case msgKindCommandComplete:
		var x xCommandComplete
		err := x.Decode(data)
		return CommandComplete(x), err
	case msgKindCopyData:
		var x xCopyData
		err := x.Decode(data)
		return CopyData(x), err
	case msgKindCopyDone:
		var x xCopyDone
		err := x.Decode(data)
		return CopyDone(x), err
	case msgKindCopyInResponse:
		var x xCopyInResponse
		err := x.Decode(data)
		return CopyInResponse(x), err
	case msgKindCopyOutResponse:
		var x xCopyOutResponse
		err := x.Decode(data)
		return CopyOutResponse(x), err
	case msgKindCopyBothResponse:
		var x xCopyBothResponse
		err := x.Decode(data)
		return CopyBothResponse(x), err
	case msgKindDataRow:
		var x xDataRow
		err := x.Decode(data)
		return DataRow(x), err
	case msgKindEmptyQueryResponse:
		var x xEmptyQueryResponse
		err := x.Decode(data)
		return EmptyQueryResponse(x), err
	case msgKindErrorResponse:
		var x xErrorResponse
		err := x.Decode(data)
		return ErrorResponse(x), err
	case msgKindFunctionCallResponse:
		var x xFunctionCallResponse
		err := x.Decode(data)
		return FunctionCallResponse(x), err
	case msgKindNegotiateProtocolVersion:
		var x xNegotiateProtocolVersion
		err := x.Decode(data)
		return NegotiateProtocolVersion(x), err
	case msgKindNoData:
		var x xNoData
		err := x.Decode(data)
		return NoData(x), err
	case msgKindNoticeResponse:
		var x xNoticeResponse
		err := x.Decode(data)
		return NoticeResponse(x), err
	case msgKindNotificationResponse:
		var x xNotificationResponse
		err := x.Decode(data)
		return NotificationResponse(x), err
	case msgKindParameterDescription:
		var x xParameterDescription
		err := x.Decode(data)
		return ParameterDescription(x), err
	case msgKindParameterStatus:
		var x xParameterStatus
		err := x.Decode(data)
		return ParameterStatus(x), err
	case msgKindParseComplete:
		var x xParseComplete
		err := x.Decode(data)
		return ParseComplete(x), err
	case msgKindPortalSuspended:
		var x xPortalSuspended
		err := x.Decode(data)
		return PortalSuspended(x), err
	case msgKindReadyForQuery:
		var x xReadyForQuery
		err := x.Decode(data)
		return ReadyForQuery(x), err
	case msgKindRowDescription:
		var x xRowDescription
		err := x.Decode(data)
		return RowDescription(x), err
	default:
		return Unknown{}, nil
	}
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

func writeByte(w io.Writer, b byte) error {
	_, err := w.Write([]byte{b})
	return err
}

func writeBytes(w io.Writer, b []byte) error {
	_, err := w.Write(b)
	return err
}

func writeInt8(w io.Writer, i int8) error {
	return writeByte(w, byte(i))
}

func writeInt16(w io.Writer, i int16) error {
	bytes := make([]byte, 2)
	binary.BigEndian.PutUint16(bytes, uint16(i))

	_, err := w.Write(bytes)
	return err
}

func writeInt32(w io.Writer, i int32) error {
	bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(bytes, uint32(i))

	_, err := w.Write(bytes)
	return err
}

func writeString(w io.Writer, s string) error {
	bytes := []byte(s)
	bytes = append(bytes, 0)

	_, err := w.Write(bytes)
	return err
}

func writeMessage(w io.Writer, kind byte, b []byte) error {
	err := writeByte(w, kind)
	if err != nil {
		return err
	}
	err = writeInt32(w, int32(len(b))+4)
	if err != nil {
		return err
	}
	return writeBytes(w, b)
}

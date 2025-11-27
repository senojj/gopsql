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

type Encoder interface {
	Encode(io.Writer) error
}

type Decoder interface {
	Decode([]byte) error
}

func parseAuthentication(kind int32, data []byte) (any, error) {
	var dec Decoder

	switch kind {
	case authKindOk:
		dec = new(AuthenticationOk)
	case authKindKerberosV5:
		dec = new(AuthenticationKerberosV5)
	case authKindCleartextPassword:
		dec = new(AuthenticationCleartextPassword)
	case authKindMD5Password:
		dec = new(AuthenticationMD5Password)
	case authKindGSS:
		dec = new(AuthenticationGSS)
	case authKindGSSContinue:
		dec = new(AuthenticationGSSContinue)
	case authKindSSPI:
		dec = new(AuthenticationSSPI)
	case authKindSASL:
		dec = new(AuthenticationSASL)
	case authKindSASLContinue:
		dec = new(AuthenticationSASLContinue)
	case authKindSASLFinal:
		dec = new(AuthenticationSASLFinal)
	default:
		dec = new(Unknown)
	}
	err := dec.Decode(data)
	if err != nil {
		return nil, err
	}
	return dec, nil
}

type AuthenticationOk struct{}

func (x *AuthenticationOk) Encode(w io.Writer) error {
	var buf bytes.Buffer
	writeInt32(&buf, authKindOk)
	return writeMessage(w, msgKindAuthentication, buf.Bytes())
}

func (x *AuthenticationOk) Decode(_ []byte) error {
	return nil
}

type AuthenticationKerberosV5 struct{}

func (x *AuthenticationKerberosV5) Encode(w io.Writer) error {
	var buf bytes.Buffer
	writeInt32(&buf, authKindKerberosV5)
	return writeMessage(w, msgKindAuthentication, buf.Bytes())
}

func (x *AuthenticationKerberosV5) Decode(_ []byte) error {
	return nil
}

type AuthenticationCleartextPassword struct{}

func (x *AuthenticationCleartextPassword) Encode(w io.Writer) error {
	var buf bytes.Buffer
	writeInt32(&buf, authKindCleartextPassword)
	return writeMessage(w, msgKindAuthentication, buf.Bytes())
}

func (x *AuthenticationCleartextPassword) Decode(_ []byte) error {
	return nil
}

type AuthenticationMD5Password struct {
	Salt [4]byte
}

func (x *AuthenticationMD5Password) Encode(w io.Writer) error {
	var buf bytes.Buffer
	writeInt32(&buf, authKindMD5Password)
	writeBytes(&buf, x.Salt[:])
	return writeMessage(w, msgKindAuthentication, buf.Bytes())
}

func (x *AuthenticationMD5Password) Decode(b []byte) error {
	copy(x.Salt[:], b)
	return nil
}

type AuthenticationGSS struct{}

func (x *AuthenticationGSS) Encode(w io.Writer) error {
	var buf bytes.Buffer
	writeInt32(&buf, authKindGSS)
	return writeMessage(w, msgKindAuthentication, buf.Bytes())
}

func (x *AuthenticationGSS) Decode(_ []byte) error {
	return nil
}

type AuthenticationGSSContinue struct {
	Data []byte
}

func (x *AuthenticationGSSContinue) Encode(w io.Writer) error {
	var buf bytes.Buffer
	writeInt32(&buf, authKindGSSContinue)
	writeBytes(&buf, x.Data)
	return writeMessage(w, msgKindAuthentication, buf.Bytes())
}

func (x *AuthenticationGSSContinue) Decode(b []byte) error {
	x.Data = make([]byte, len(b))
	copy(x.Data, b)
	return nil
}

type AuthenticationSSPI struct{}

func (x *AuthenticationSSPI) Encode(w io.Writer) error {
	var buf bytes.Buffer
	writeInt32(&buf, authKindSSPI)
	return writeMessage(w, msgKindAuthentication, buf.Bytes())
}

func (x *AuthenticationSSPI) Decode(_ []byte) error {
	return nil
}

type AuthenticationSASL struct {
	Mechanisms []string
}

func (x *AuthenticationSASL) Encode(w io.Writer) error {
	var buf bytes.Buffer
	writeInt32(&buf, authKindSASL)
	for i := range len(x.Mechanisms) {
		writeString(&buf, x.Mechanisms[i])
	}
	return writeMessage(w, msgKindAuthentication, buf.Bytes())
}

func (x *AuthenticationSASL) Decode(b []byte) error {
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

func (x *AuthenticationSASLContinue) Encode(w io.Writer) error {
	var buf bytes.Buffer
	writeInt32(&buf, authKindSASLContinue)
	writeBytes(&buf, x.Data)
	return writeMessage(w, msgKindAuthentication, buf.Bytes())
}

func (x *AuthenticationSASLContinue) Decode(b []byte) error {
	x.Data = make([]byte, len(b))
	copy(x.Data, b)
	return nil
}

type AuthenticationSASLFinal struct {
	Data []byte
}

func (x *AuthenticationSASLFinal) Encode(w io.Writer) error {
	var buf bytes.Buffer
	writeInt32(&buf, authKindSASLFinal)
	writeBytes(&buf, x.Data)
	return writeMessage(w, msgKindAuthentication, buf.Bytes())
}

func (x *AuthenticationSASLFinal) Decode(b []byte) error {
	x.Data = make([]byte, len(b))
	copy(x.Data, b)
	return nil
}

type BackendKeyData struct {
	ProcessID int32
	SecretKey []byte
}

func (x *BackendKeyData) Encode(w io.Writer) error {
	var buf bytes.Buffer
	writeInt32(&buf, x.ProcessID)
	writeBytes(&buf, x.SecretKey)
	return writeMessage(w, msgKindKeyData, buf.Bytes())
}

func (x *BackendKeyData) Decode(b []byte) error {
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

func (x *BindComplete) Encode(w io.Writer) error {
	return writeMessage(w, msgKindBindComplete, []byte{})
}

func (x *BindComplete) Decode(_ []byte) error {
	return nil
}

type CloseComplete struct{}

func (x *CloseComplete) Encode(w io.Writer) error {
	return writeMessage(w, msgKindCloseComplete, []byte{})
}

func (x *CloseComplete) Decode(_ []byte) error {
	return nil
}

type CommandComplete struct {
	Tag string
}

func (x *CommandComplete) Encode(w io.Writer) error {
	var buf bytes.Buffer
	writeString(&buf, x.Tag)
	return writeMessage(w, msgKindCommandComplete, buf.Bytes())
}

func (x *CommandComplete) Decode(b []byte) error {
	_, err := readString(b, &x.Tag)
	return err
}

type CopyData struct {
	Data []byte
}

func (x *CopyData) Encode(w io.Writer) error {
	var buf bytes.Buffer
	writeBytes(&buf, x.Data)
	return writeMessage(w, msgKindCopyData, buf.Bytes())
}

func (x *CopyData) Decode(b []byte) error {
	x.Data = make([]byte, len(b))
	copy(x.Data, b)
	return nil
}

type CopyDone struct{}

func (x *CopyDone) Encode(w io.Writer) error {
	return writeMessage(w, msgKindCopyDone, []byte{})
}

func (x *CopyDone) Decode(_ []byte) error {
	return nil
}

type CopyInResponse struct {
	Format  int8
	Columns []int16
}

func (x *CopyInResponse) Encode(w io.Writer) error {
	var buf bytes.Buffer
	writeInt8(&buf, x.Format)
	writeInt16(&buf, int16(len(x.Columns)))
	for _, f := range x.Columns {
		writeInt16(&buf, f)
	}
	return writeMessage(w, msgKindCopyInResponse, buf.Bytes())
}

func (x *CopyInResponse) Decode(b []byte) error {
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

func (x *CopyOutResponse) Encode(w io.Writer) error {
	var buf bytes.Buffer
	writeInt8(&buf, x.Format)
	writeInt16(&buf, int16(len(x.Columns)))
	for _, f := range x.Columns {
		writeInt16(&buf, f)
	}
	return writeMessage(w, msgKindCopyOutResponse, buf.Bytes())
}

func (x *CopyOutResponse) Decode(b []byte) error {
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

func (x *CopyBothResponse) Encode(w io.Writer) error {
	var buf bytes.Buffer
	writeInt8(&buf, x.Format)
	writeInt16(&buf, int16(len(x.Columns)))
	for _, f := range x.Columns {
		writeInt16(&buf, f)
	}
	return writeMessage(w, msgKindCopyBothResponse, buf.Bytes())
}

func (x *CopyBothResponse) Decode(b []byte) error {
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

func (x *DataRow) Encode(w io.Writer) error {
	var buf bytes.Buffer
	writeInt16(&buf, int16(len(x.Columns)))
	for _, column := range x.Columns {
		if column == nil {
			writeInt32(&buf, -1)
			continue
		}
		writeInt32(&buf, int32(len(column)))
		writeBytes(&buf, column)
	}
	return writeMessage(w, msgKindDataRow, buf.Bytes())
}

func (x *DataRow) Decode(b []byte) error {
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

func (x *EmptyQueryResponse) Encode(w io.Writer) error {
	return writeMessage(w, msgKindEmptyQueryResponse, []byte{})
}

func (x *EmptyQueryResponse) Decode(_ []byte) error {
	return nil
}

type ErrorResponse struct {
	Fields []byte
	Values []string
}

func (x *ErrorResponse) Encode(w io.Writer) error {
	var buf bytes.Buffer
	for i := range len(x.Fields) {
		writeByte(&buf, x.Fields[i])
		writeString(&buf, x.Values[i])
	}
	writeByte(&buf, 0)
	return writeMessage(w, msgKindErrorResponse, buf.Bytes())
}

func (x *ErrorResponse) Decode(b []byte) error {
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

func (x *FunctionCallResponse) Encode(w io.Writer) error {
	var buf bytes.Buffer
	if x.Result == nil {
		writeInt32(&buf, -1)
	} else {
		writeInt32(&buf, int32(len(x.Result)))
	}
	writeBytes(&buf, x.Result)
	return writeMessage(w, msgKindFunctionCallResponse, buf.Bytes())
}

func (x *FunctionCallResponse) Decode(b []byte) error {
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

func (x *NegotiateProtocolVersion) Encode(w io.Writer) error {
	var buf bytes.Buffer
	writeInt32(&buf, x.MinorVersionSupported)
	writeInt32(&buf, int32(len(x.UnrecognizedOptions)))
	for _, option := range x.UnrecognizedOptions {
		writeString(&buf, option)
	}
	return writeMessage(w, msgKindNegotiateProtocolVersion, buf.Bytes())
}

func (x *NegotiateProtocolVersion) Decode(b []byte) error {
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

func (x *NoData) Encode(w io.Writer) error {
	return writeMessage(w, msgKindNoData, []byte{})
}

func (x *NoData) Decode(_ []byte) error {
	return nil
}

type NoticeResponse struct {
	Fields []byte
	Values []string
}

func (x *NoticeResponse) Encode(w io.Writer) error {
	var buf bytes.Buffer
	for i := range len(x.Fields) {
		writeByte(&buf, x.Fields[i])
		writeString(&buf, x.Values[i])
	}
	writeByte(&buf, 0)
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

type NotificationResponse struct {
	ProcessID int32
	Channel   string
	Payload   string
}

func (x *NotificationResponse) Encode(w io.Writer) error {
	var buf bytes.Buffer
	writeInt32(&buf, x.ProcessID)
	writeString(&buf, x.Channel)
	writeString(&buf, x.Payload)
	return writeMessage(w, msgKindNotificationResponse, buf.Bytes())
}

func (x *NotificationResponse) Decode(b []byte) error {
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

func (x *ParameterDescription) Encode(w io.Writer) error {
	var buf bytes.Buffer
	writeInt16(&buf, int16(len(x.Parameters)))
	for _, param := range x.Parameters {
		writeInt32(&buf, param)
	}
	return writeMessage(w, msgKindParameterDescription, buf.Bytes())
}

func (x *ParameterDescription) Decode(b []byte) error {
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

func (x *ParameterStatus) Encode(w io.Writer) error {
	var buf bytes.Buffer
	writeString(&buf, x.Name)
	writeString(&buf, x.Value)
	return writeMessage(w, msgKindParameterStatus, buf.Bytes())
}

func (x *ParameterStatus) Decode(b []byte) error {
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

func (x *ParseComplete) Encode(w io.Writer) error {
	return writeMessage(w, msgKindParseComplete, []byte{})
}

func (x *ParseComplete) Decode(_ []byte) error {
	return nil
}

type PortalSuspended struct{}

func (x *PortalSuspended) Encode(w io.Writer) error {
	return writeMessage(w, msgKindPortalSuspended, []byte{})
}

func (x *PortalSuspended) Decode(_ []byte) error {
	return nil
}

type ReadyForQuery struct {
	TxStatus byte
}

func (x *ReadyForQuery) Encode(w io.Writer) error {
	var buf bytes.Buffer
	writeByte(&buf, x.TxStatus)
	return writeMessage(w, msgKindReadyForQuery, buf.Bytes())
}

func (x *ReadyForQuery) Decode(b []byte) error {
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

func (x *RowDescription) Encode(w io.Writer) error {
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

func (x *RowDescription) Decode(b []byte) error {
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

func (x *Unknown) Encode(_ io.Writer) error {
	return ErrInvalidValue
}

func (x *Unknown) Decode(_ []byte) error {
	return ErrInvalidValue
}

func parseMessage(kind byte, data []byte) (any, error) {
	var dec Decoder

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
		dec = new(BackendKeyData)
	case msgKindBindComplete:
		dec = new(BindComplete)
	case msgKindCloseComplete:
		dec = new(CloseComplete)
	case msgKindCommandComplete:
		dec = new(CommandComplete)
	case msgKindCopyData:
		dec = new(CopyData)
	case msgKindCopyDone:
		dec = new(CopyDone)
	case msgKindCopyInResponse:
		dec = new(CopyInResponse)
	case msgKindCopyOutResponse:
		dec = new(CopyOutResponse)
	case msgKindCopyBothResponse:
		dec = new(CopyBothResponse)
	case msgKindDataRow:
		dec = new(DataRow)
	case msgKindEmptyQueryResponse:
		dec = new(EmptyQueryResponse)
	case msgKindErrorResponse:
		dec = new(ErrorResponse)
	case msgKindFunctionCallResponse:
		dec = new(FunctionCallResponse)
	case msgKindNegotiateProtocolVersion:
		dec = new(NegotiateProtocolVersion)
	case msgKindNoData:
		dec = new(NoData)
	case msgKindNoticeResponse:
		dec = new(NoticeResponse)
	case msgKindNotificationResponse:
		dec = new(NotificationResponse)
	case msgKindParameterDescription:
		dec = new(ParameterDescription)
	case msgKindParameterStatus:
		dec = new(ParameterStatus)
	case msgKindParseComplete:
		dec = new(ParseComplete)
	case msgKindPortalSuspended:
		dec = new(PortalSuspended)
	case msgKindReadyForQuery:
		dec = new(ReadyForQuery)
	case msgKindRowDescription:
		dec = new(RowDescription)
	default:
		dec = new(Unknown)
	}
	err := dec.Decode(data)
	if err != nil {
		return nil, err
	}
	return dec, nil
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

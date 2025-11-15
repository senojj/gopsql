package backend

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

var (
	ErrShortRead     = errors.New("short read")
	ErrValueOverflow = errors.New("value too large")
	ErrInvalidValue  = errors.New("invalid value")
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
	KindReadyForQuey             Kind = 'Z'
	KindRowDescription           Kind = 'T'
)

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

type TxStatus byte

const (
	TxStatusIdle   TxStatus = 'I'
	TxStatusActive TxStatus = 'T'
	TxStatusError  TxStatus = 'E'
)

type AuthenticationOk struct{}

type xAuthenticationOk AuthenticationOk

func (x *xAuthenticationOk) Unmarshal(_ []byte) error {
	return nil
}

type AuthenticationKerberosV5 struct{}

type xAuthenticationKerberosV5 AuthenticationKerberosV5

func (x *xAuthenticationKerberosV5) Unmarshal(_ []byte) error {
	return nil
}

type AuthenticationCleartextPassword struct{}

type xAuthenticationCleartextPassword AuthenticationCleartextPassword

func (x *xAuthenticationCleartextPassword) Unmarshal(_ []byte) error {
	return nil
}

type AuthenticationMD5Password struct {
	Salt [4]byte
}

type xAuthenticationMD5Password AuthenticationMD5Password

func (x *xAuthenticationMD5Password) Unmarshal(b []byte) error {
	copy(x.Salt[:], b)
	return nil
}

type AuthenticationGSS struct{}

type xAuthenticationGSS AuthenticationGSS

func (x *xAuthenticationGSS) Unmarshal(_ []byte) error {
	return nil
}

type AuthenticationGSSContinue struct {
	Data []byte
}

type xAuthenticationGSSContinue AuthenticationGSSContinue

func (x *xAuthenticationGSSContinue) Unmarshal(b []byte) error {
	x.Data = make([]byte, len(b))
	copy(x.Data, b)
	return nil
}

type AuthenticationSSPI struct{}

type xAuthenticationSSPI AuthenticationSSPI

func (x *xAuthenticationSSPI) Unmarshal(_ []byte) error {
	return nil
}

type AuthenticationSASL struct {
	Mechanisms []string
}

type xAuthenticationSASL AuthenticationSASL

func (x *xAuthenticationSASL) Unmarshal(b []byte) error {
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

func (x *xAuthenticationSASLContinue) Unmarshal(b []byte) error {
	x.Data = make([]byte, len(b))
	copy(x.Data, b)
	return nil
}

type AuthenticationSASLFinal struct {
	Data []byte
}

type xAuthenticationSASLFinal AuthenticationSASLFinal

func (x *xAuthenticationSASLFinal) Unmarshal(b []byte) error {
	x.Data = make([]byte, len(b))
	copy(x.Data, b)
	return nil
}

type BackendKeyData struct {
	ProcessID int32
	SecretKey []byte
}

type xBackendKeyData BackendKeyData

func (x *xBackendKeyData) Unmarshal(b []byte) error {
	if len(b) < 4 {
		return ErrShortRead
	}
	bread, err := readInt32(b, &x.ProcessID)
	if err != nil {
		return err
	}
	b = b[bread:]

	if len(b) < 4 {
		return ErrShortRead
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

func (x *xBindComplete) Unmarshal(_ []byte) error {
	return nil
}

type CloseComplete struct{}

type xCloseComplete CloseComplete

func (x *xCloseComplete) Unmarshal(_ []byte) error {
	return nil
}

type CommandComplete struct {
	Tag string
}

type xCommandComplete CommandComplete

func (x *xCommandComplete) Unmarshal(b []byte) error {
	_, err := readString(b, &x.Tag)
	return err
}

type CopyData struct {
	Data []byte
}

type xCopyData CopyData

func (x *xCopyData) Unmarshal(b []byte) error {
	x.Data = make([]byte, len(b))
	copy(x.Data, b)
	return nil
}

type CopyDone struct{}

type xCopyDone CopyDone

func (x *xCopyDone) Unmarshal(_ []byte) error {
	return nil
}

type CopyInResponse struct {
	Format  Format
	Columns []Format
}

type xCopyInResponse CopyInResponse

func (x *xCopyInResponse) Unmarshal(b []byte) error {
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
		return ErrShortRead
	}

	x.Format = Format(format)
	x.Columns = make([]Format, int(columns))
	for i := range len(x.Columns) {
		var format int16
		bread, err = readInt16(b, &format)
		if err != nil {
			return err
		}
		b = b[bread:]
		x.Columns[i] = Format(format)
	}
	return nil
}

type CopyOutResponse struct {
	Format  Format
	Columns []Format
}

type xCopyOutResponse CopyOutResponse

func (x *xCopyOutResponse) Unmarshal(b []byte) error {
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
		return ErrShortRead
	}

	x.Format = Format(format)
	x.Columns = make([]Format, int(columns))
	for i := range len(x.Columns) {
		var format int16
		bread, err = readInt16(b, &format)
		if err != nil {
			return err
		}
		b = b[bread:]
		x.Columns[i] = Format(format)
	}
	return nil
}

type CopyBothResponse struct {
	Format  Format
	Columns []Format
}

type xCopyBothResponse CopyBothResponse

func (x *xCopyBothResponse) Unmarshal(b []byte) error {
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
		return ErrShortRead
	}

	x.Format = Format(format)
	x.Columns = make([]Format, int(columns))
	for i := range len(x.Columns) {
		var format int16
		bread, err = readInt16(b, &format)
		if err != nil {
			return err
		}
		b = b[bread:]
		x.Columns[i] = Format(format)
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

func (x *xDataRow) Unmarshal(b []byte) error {
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

func (x *xEmptyQueryResponse) Unmarshal(_ []byte) error {
	return nil
}

type ErrorResponse struct {
	Fields []Field
	Values []string
}

type xErrorResponse ErrorResponse

func (x *xErrorResponse) Unmarshal(b []byte) error {
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

func (x *xFunctionCallResponse) Unmarshal(b []byte) error {
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

func (x *xNegotiateProtocolVersion) Unmarshal(b []byte) error {
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

func (x *xNoData) Unmarshal(_ []byte) error {
	return nil
}

type NoticeResponse struct {
	Fields []Field
	Values []string
}

type xNoticeResponse NoticeResponse

func (x *xNoticeResponse) Unmarshal(b []byte) error {
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

func (x *xNotificationResponse) Unmarshal(b []byte) error {
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

func (x *xParameterDescription) Unmarshal(b []byte) error {
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

type ParseComplete struct{}

type PortalSuspended struct{}

type ReadyForQuery struct {
	TxStatus TxStatus
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

type Unknown struct{}

type Message struct {
	kind Kind
	body []byte
}

func (m *Message) Unmarshal(r io.Reader) error {
	var byteKind [1]byte
	var byteLength [4]byte

	bread, err := r.Read(byteKind[:])
	if err != nil {
		return err
	}

	if bread != 1 {
		return ErrShortRead
	}

	bread, err = r.Read(byteLength[:])
	if err != nil {
		if err == io.EOF {
			return ErrShortRead
		}
		return err
	}

	if bread != 4 {
		return ErrShortRead
	}

	m.kind = Kind(byteKind[0])
	length := int32(binary.BigEndian.Uint32(byteLength[:])) - 4

	byteBody := make([]byte, int(length))

	bread, err = r.Read(byteBody)
	if err != nil {
		if err == io.EOF {
			return ErrShortRead
		}
		return err
	}

	if bread != int(length) {
		return ErrShortRead
	}
	m.body = byteBody

	return nil
}

func (m *Message) Parse() (any, error) {
	switch m.kind {
	case KindAuthentication:
		var s int32
		bread, err := readInt32(m.body, &s)
		if err != nil {
			return nil, err
		}
		b := m.body[bread:]

		switch s {
		case 0:
			var x xAuthenticationOk
			err := x.Unmarshal(b)
			return AuthenticationOk(x), err
		case 2:
			var x xAuthenticationKerberosV5
			err := x.Unmarshal(b)
			return AuthenticationKerberosV5(x), err
		case 3:
			var x xAuthenticationCleartextPassword
			err := x.Unmarshal(b)
			return AuthenticationCleartextPassword(x), err
		case 5:
			var x xAuthenticationMD5Password
			err := x.Unmarshal(b)
			return AuthenticationMD5Password(x), err
		case 7:
			var x xAuthenticationGSS
			err := x.Unmarshal(b)
			return AuthenticationGSS(x), err
		case 8:
			var x xAuthenticationGSSContinue
			err := x.Unmarshal(b)
			return AuthenticationGSSContinue(x), err
		case 9:
			var x xAuthenticationSSPI
			err := x.Unmarshal(b)
			return AuthenticationSSPI(x), err
		case 10:
			var x xAuthenticationSASL
			err := x.Unmarshal(b)
			return AuthenticationSASL(x), err
		case 11:
			var x xAuthenticationSASLContinue
			err := x.Unmarshal(b)
			return AuthenticationSASLContinue(x), err
		case 12:
			var x xAuthenticationSASLFinal
			err := x.Unmarshal(b)
			return AuthenticationSASLFinal(x), err
		default:
			return Unknown{}, nil
		}
	case KindKeyData:
		var x xBackendKeyData
		err := x.Unmarshal(m.body)
		return BackendKeyData(x), err
	case KindBindComplete:
		var x xBindComplete
		err := x.Unmarshal(m.body)
		return BindComplete(x), err
	case KindCloseComplete:
		var x xCloseComplete
		err := x.Unmarshal(m.body)
		return CloseComplete(x), err
	case KindCommandComplete:
		var x xCommandComplete
		err := x.Unmarshal(m.body)
		return CommandComplete(x), err
	case KindCopyData:
		var x xCopyData
		err := x.Unmarshal(m.body)
		return CopyData(x), err
	case KindCopyDone:
		var x xCopyDone
		err := x.Unmarshal(m.body)
		return CopyDone(x), err
	case KindCopyInResponse:
		var x xCopyInResponse
		err := x.Unmarshal(m.body)
		return CopyInResponse(x), err
	case KindCopyOutResponse:
		var x xCopyOutResponse
		err := x.Unmarshal(m.body)
		return CopyOutResponse(x), err
	case KindCopyBothResponse:
		var x xCopyBothResponse
		err := x.Unmarshal(m.body)
		return CopyBothResponse(x), err
	case KindDataRow:
		var x xDataRow
		err := x.Unmarshal(m.body)
		return DataRow(x), err
	case KindEmptyQueryResponse:
		var x xEmptyQueryResponse
		err := x.Unmarshal(m.body)
		return EmptyQueryResponse(x), err
	case KindErrorResponse:
		var x xErrorResponse
		err := x.Unmarshal(m.body)
		return ErrorResponse(x), err
	case KindFunctionCallResponse:
		var x xFunctionCallResponse
		err := x.Unmarshal(m.body)
		return FunctionCallResponse(x), err
	case KindNegotiateProtocolVersion:
		var x xNegotiateProtocolVersion
		err := x.Unmarshal(m.body)
		return NegotiateProtocolVersion(x), err
	case KindNoData:
		var x xNoData
		err := x.Unmarshal(m.body)
		return NoData(x), err
	case KindNoticeResponse:
		var x xNoticeResponse
		err := x.Unmarshal(m.body)
		return NoticeResponse(x), err
	case KindNotificationResponse:
		var x xNotificationResponse
		err := x.Unmarshal(m.body)
		return NotificationResponse(x), err
	case KindParameterDescription:
		var x xParameterDescription
		err := x.Unmarshal(m.body)
		return ParameterDescription(x), err
	default:
		return Unknown{}, nil
	}
}

func readByte(b []byte, v *byte) (int, error) {
	if len(b) < 1 {
		return 0, ErrShortRead
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
		return 0, ErrShortRead
	}
	*i = int16(binary.BigEndian.Uint16(b[:2]))
	return 2, nil
}

func readInt32(b []byte, i *int32) (int, error) {
	if len(b) < 4 {
		return 0, ErrShortRead
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
	return 0, ErrShortRead
}

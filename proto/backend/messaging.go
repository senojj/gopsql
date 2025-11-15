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

type xCopyBothResopnse CopyBothResponse

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

func (n *NoticeResponse) Unmarshal(b []byte) error {
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
		n.Fields = append(n.Fields, Field(field))
		var value string
		bread, err = readString(b, &value)
		if err != nil {
			return err
		}
		b = b[bread:]
		n.Values = append(n.Values, value)
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

func (n *NotificationResponse) Unmarshal(b []byte) error {
	bread, err := readInt32(b, &n.ProcessID)
	if err != nil {
		return err
	}
	b = b[bread:]

	bread, err = readString(b, &n.Channel)
	if err != nil {
		return err
	}
	b = b[bread:]

	bread, err = readString(b, &n.Payload)
	if err != nil {
		return err
	}
	return nil
}

type ParameterDescription struct {
	Parameters []int32
}

func (p *ParameterDescription) Unmarshal(b []byte) error {
	var length int16
	bread, err := readInt16(b, &length)
	if err != nil {
		return err
	}
	b = b[bread:]

	p.Parameters = make([]int32, length)

	for i := range length {
		var param int32
		bread, err = readInt32(b, &param)
		if err != nil {
			return err
		}
		p.Parameters[i] = param
		b = b[bread:]
	}
	return nil
}

type ParametetrStatus struct {
	Name  string
	Value string
}

type ParseComplete struct {
	noop
}

type PortalSuspended struct {
	noop
}

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

type Unknown struct {
	noop
}

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
			var a AuthenticationGSS
			err := a.Unmarshal(b)
			return a, err
		case 8:
			var a AuthenticationGSSContinue
			err := a.Unmarshal(b)
			return a, err
		case 9:
			var a AuthenticationSSPI
			err := a.Unmarshal(b)
			return a, err
		case 10:
			var a AuthenticationSASL
			err := a.Unmarshal(b)
			return a, err
		case 11:
			var a AuthenticationSASLContinue
			err := a.Unmarshal(b)
			return a, err
		case 12:
			var a AuthenticationSASLFinal
			err := a.Unmarshal(b)
			return a, err
		default:
			var a Unknown
			err := a.Unmarshal(b)
			return a, err
		}
	case KindKeyData:
		var k BackendKeyData
		err := k.Unmarshal(m.body)
		return k, err
	case KindBindComplete:
		var c BindComplete
		err := c.Unmarshal(m.body)
		return c, err
	case KindCloseComplete:
		var c CloseComplete
		err := c.Unmarshal(m.body)
		return c, err
	case KindCommandComplete:
		var c CommandComplete
		err := c.Unmarshal(m.body)
		return c, err
	case KindCopyData:
		var c CopyData
		err := c.Unmarshal(m.body)
		return c, err
	case KindCopyDone:
		var c CopyDone
		err := c.Unmarshal(m.body)
		return c, err
	case KindCopyInResponse:
		var c CopyInResponse
		err := c.Unmarshal(m.body)
		return c, err
	case KindCopyOutResponse:
		var c CopyOutResponse
		err := c.Unmarshal(m.body)
		return c, err
	case KindCopyBothResponse:
		var c CopyBothResponse
		err := c.Unmarshal(m.body)
		return c, err
	case KindDataRow:
		var d DataRow
		err := d.Unmarshal(m.body)
		return d, err
	case KindEmptyQueryResponse:
		var e EmptyQueryResponse
		err := e.Unmarshal(m.body)
		return e, err
	case KindErrorResponse:
		var e ErrorResponse
		err := e.Unmarshal(m.body)
		return e, err
	case KindFunctionCallResponse:
		var f FunctionCallResponse
		err := f.Unmarshal(m.body)
		return f, err
	case KindNegotiateProtocolVersion:
		var n NegotiateProtocolVersion
		err := n.Unmarshal(m.body)
		return n, err
	case KindNoData:
		var n NoData
		err := n.Unmarshal(m.body)
		return n, err
	case KindNoticeResponse:
		var n NoticeResponse
		err := n.Unmarshal(m.body)
		return n, err
	case KindNotificationResponse:
		var n NotificationResponse
		err := n.Unmarshal(m.body)
		return n, err
	case KindParameterDescription:
		var p ParameterDescription
		err := p.Unmarshal(m.body)
		return p, err
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

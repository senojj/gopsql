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

type Unmarshaler interface {
	Unmarshal([]byte) error
}

type noop struct{}

func (n *noop) Unmarshal(b []byte) error {
	return nil
}

type AuthenticationOk struct {
	noop
}

type AuthenticationKerberosV5 struct {
	noop
}

type AuthenticationCleartextPassword struct {
	noop
}

type AuthenticationMD5Password struct {
	Salt [4]byte
}

func (a *AuthenticationMD5Password) Unmarshal(b []byte) error {
	copy(a.Salt[:], b)
	return nil
}

type AuthenticationGSS struct {
	noop
}

type AuthenticationGSSContinue struct {
	Data []byte
}

func (a *AuthenticationGSSContinue) Unmarshal(b []byte) error {
	a.Data = make([]byte, len(b))
	copy(a.Data, b)
	return nil
}

type AuthenticationSSPI struct {
	noop
}

type AuthenticationSASL struct {
	Mechanisms []string
}

func (a *AuthenticationSASL) Unmarshal(b []byte) error {
	for len(b) > 1 {
		var mechanism string
		mechanism, b = readString(b)
		a.Mechanisms = append(a.Mechanisms, mechanism)
	}
	return nil
}

type AuthenticationSASLContinue struct {
	Data []byte
}

func (a *AuthenticationSASLContinue) Unmarshal(b []byte) error {
	a.Data = make([]byte, len(b))
	copy(a.Data, b)
	return nil
}

type AuthenticationSASLFinal struct {
	Data []byte
}

func (a *AuthenticationSASLFinal) Unmarshal(b []byte) error {
	a.Data = make([]byte, len(b))
	copy(a.Data, b)
	return nil
}

type BackendKeyData struct {
	ProcessID int32
	SecretKey []byte
}

func (k *BackendKeyData) Unmarshal(b []byte) error {
	if len(b) < 4 {
		return ErrShortRead
	}
	processID, b := readInt32(b)
	k.ProcessID = processID
	if len(b) < 4 {
		return ErrShortRead
	}
	if len(b) > 256 {
		return ErrValueOverflow
	}
	k.SecretKey = make([]byte, len(b))
	copy(k.SecretKey, b)
	return nil
}

type BindComplete struct {
	noop
}

type CloseComplete struct {
	noop
}

type CommandComplete struct {
	Tag string
}

func (c *CommandComplete) Unmarshal(b []byte) error {
	tag, _ := readString(b)
	c.Tag = tag
	return nil
}

type CopyData struct {
	Data []byte
}

func (c *CopyData) Unmarshal(b []byte) error {
	c.Data = make([]byte, len(b))
	copy(c.Data, b)
	return nil
}

type CopyDone struct {
	noop
}

type CopyInResponse struct {
	Format  Format
	Columns []Format
}

func (c *CopyInResponse) Unmarshal(b []byte) error {
	format, b := readInt8(b)
	if len(b) < 2 {
		return ErrShortRead
	}
	columns, b := readInt16(b)
	if len(b) < int(columns)*2 {
		return ErrShortRead
	}
	c.Format = Format(format)
	c.Columns = make([]Format, int(columns))
	for i := range len(c.Columns) {
		var format int16
		format, b = readInt16(b)
		c.Columns[i] = Format(format)
	}
	return nil
}

type CopyOutResponse struct {
	Format  Format
	Columns []Format
}

func (c *CopyOutResponse) Unmarshal(b []byte) error {
	format, b := readInt8(b)
	if len(b) < 2 {
		return ErrShortRead
	}
	columns, b := readInt16(b)
	if len(b) < int(columns)*2 {
		return ErrShortRead
	}
	c.Format = Format(format)
	c.Columns = make([]Format, int(columns))
	for i := range len(c.Columns) {
		var format int16
		format, b = readInt16(b)
		c.Columns[i] = Format(format)
	}
	return nil
}

type CopyBothResponse struct {
	Format  Format
	Columns []Format
}

func (c *CopyBothResponse) Unmarshal(b []byte) error {
	format, b := readInt8(b)
	if len(b) < 2 {
		return ErrShortRead
	}
	columns, b := readInt16(b)
	if len(b) < int(columns)*2 {
		return ErrShortRead
	}
	c.Format = Format(format)
	c.Columns = make([]Format, int(columns))
	for i := range len(c.Columns) {
		var format int16
		format, b = readInt16(b)
		c.Columns[i] = Format(format)
	}
	return nil
}

type DataRow struct {
	// First dimention is columns (can have 0 elements).
	// Second dimension is value data (can have 0 elements
	// or be nil).
	Columns [][]byte
}

func (d *DataRow) Unmarshal(b []byte) error {
	columns, b := readInt16(b)
	d.Columns = make([][]byte, columns)

	for i := range columns {
		if len(b) < 4 {
			return ErrShortRead
		}
		var length int32
		length, b = readInt32(b)
		if length == -1 {
			d.Columns[i] = nil
			continue
		}
		d.Columns[i] = make([]byte, length)
		copy(d.Columns[i], b[:length])
		b = b[length:]
	}
	return nil
}

type EmptyQueryResponse struct {
	noop
}

type ErrorResponse struct {
	Fields []Field
	Values []string
}

func (e *ErrorResponse) Unmarshal(b []byte) error {
	var f byte

	f, b = readByte(b)
	for f != 0 {
		field, err := ParseField(f)
		if err != nil {
			return err
		}
		e.Fields = append(e.Fields, Field(field))
		var value string
		value, b = readString(b)
		e.Values = append(e.Values, value)
		f, b = readByte(b)
	}
	return nil
}

type FunctionCallResponse struct {
	// Can be zero length or nil.
	Result []byte
}

type NegotiateProtocolVersion struct {
	MinorVersionSupported int32
	UnrecognizedOptions   []string
}

type NoData struct {
	noop
}

type NoticeResponse struct {
	Fields []Field
	Values []string
}

type NotificationResponse struct {
	ProcessID int32
	Channel   string
	Payload   string
}

type ParameterDescription struct {
	Parameters []int32
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
		s, b := readInt32(m.body)
		switch s {
		case 0:
			var a AuthenticationOk
			err := a.Unmarshal(b)
			return a, err
		case 2:
			var a AuthenticationKerberosV5
			err := a.Unmarshal(b)
			return a, err
		case 3:
			var a AuthenticationCleartextPassword
			err := a.Unmarshal(b)
			return a, err
		case 5:
			var a AuthenticationMD5Password
			err := a.Unmarshal(b)
			return a, err
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
	default:
		return Unknown{}, nil
	}
}

func readByte(b []byte) (byte, []byte) {
	var v byte
	if len(b) > 0 {
		v = b[0]
		return v, b[1:]
	}
	return v, nil
}

func readInt8(b []byte) (int8, []byte) {
	var v int8
	if len(b) > 0 {
		v = int8(b[0])
		return v, b[1:]
	}
	return v, nil
}

func readInt16(b []byte) (int16, []byte) {
	var v int16
	if len(b) > 1 {
		v = int16(binary.BigEndian.Uint16(b[:2]))
		return v, b[2:]
	}
	return v, nil
}

func readInt32(b []byte) (int32, []byte) {
	var v int32
	if len(b) > 3 {
		v = int32(binary.BigEndian.Uint32(b[:4]))
		return v, b[4:]
	}
	return v, nil
}

func readString(b []byte) (string, []byte) {
	ndx := bytes.IndexByte(b, 0)
	if ndx > -1 {
		return string(b[:ndx]), b[ndx+1:]
	}
	return string(b), nil
}

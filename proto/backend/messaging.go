package backend

import (
	"encoding/binary"
	"errors"
	"io"
	"strings"
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

type Format int

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

type (
	AuthenticationOk struct{}

	AuthenticationKerberosV5 struct{}

	AuthenticationCleartextPassword struct{}

	AuthenticationMD5Password struct {
		Salt [4]byte
	}

	AuthenticationGSS struct{}

	AuthenticationGSSContinue struct {
		Data []byte
	}

	AuthenticationSSPI struct{}

	AuthenticationSASL struct {
		Mechanisms []string
	}

	AuthenticationSASLContinue struct {
		Data []byte
	}

	AuthenticationSASLFinal struct {
		Data []byte
	}

	BackendKeyData struct {
		ProcessID int32
		SecretKey []byte
	}

	BindComplete struct{}

	CloseComplete struct{}

	CommandComplete struct {
		Tag string
	}

	CopyData struct {
		Data []byte
	}

	CopyDone struct{}

	CopyInResponse struct {
		Format  Format
		Columns []Format
	}

	CopyOutResponse struct {
		Format  Format
		Columns []Format
	}

	CopyBothResponse struct {
		Format  Format
		Columns []Format
	}

	DataRow struct {
		// First dimention is columns (can have 0 elements).
		// Second dimension is value data (can have 0 elements
		// or be nil).
		Columns [][]byte
	}

	EmptyQueryResponse struct{}

	ErrorResponse struct {
		Types  []byte
		Values []string
	}

	FunctionCallResponse struct {
		// Can be zero length or nil.
		Result []byte
	}

	NegotiateProtocolVersion struct {
		MinorVersionSupported int32
		UnrecognizedOptions   []string
	}

	NoData struct{}

	NoticeResponse struct {
		Types  []byte
		Values []string
	}

	NotificationResponse struct {
		ProcessID int32
		Channel   string
		Payload   string
	}

	ParameterDescription struct {
		Parameters []int32
	}

	ParametetrStatus struct {
		Name  string
		Value string
	}

	ParseComplete struct{}

	PortalSuspended struct{}

	ReadyForQuery struct {
		TxStatus TxStatus
	}

	RowDescription struct {
		Names     []string
		Tables    []int32
		Columns   []int16
		DataTypes []int32
		Sizes     []int16
		Modifiers []int32
		Formats   []Format
	}

	Unknown struct{}
)

var ErrShortRead = errors.New("short read")

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
		s := int32(binary.BigEndian.Uint32(m.body[:4]))
		switch s {
		case 0:
			return AuthenticationOk{}, nil
		case 2:
			return AuthenticationKerberosV5{}, nil
		case 3:
			return AuthenticationCleartextPassword{}, nil
		case 5:
			var a AuthenticationMD5Password
			copy(a.Salt[:], m.body[4:])
			return a, nil
		case 7:
			return AuthenticationGSS{}, nil
		case 8:
			var a AuthenticationGSSContinue
			copy(a.Data, m.body[4:])
			return a, nil
		case 9:
			return AuthenticationSSPI{}, nil
		case 10:
			return AuthenticationSASL{}, nil
		case 11:
			var a AuthenticationSASLContinue
			copy(a.Data, m.body[4:])
			return a, nil
		case 12:
			var a AuthenticationSASLFinal
			copy(a.Data, m.body[4:])
			return a, nil
		default:
			return Unknown{}, nil
		}
	case KindKeyData:
		processID := int32(binary.BigEndian.Uint32(m.body[:4]))
		var k BackendKeyData
		k.ProcessID = processID
		copy(k.SecretKey, m.body[4:])
		return k, nil
	case KindBindComplete:
		return BindComplete{}, nil
	case KindCloseComplete:
		return CloseComplete{}, nil
	case KindCommandComplete:
		var c CommandComplete
		var sb strings.Builder
		for _, v := range m.body {
			if v == '\x00' {
				break
			}
			sb.WriteByte(v)
		}
		c.Tag = sb.String()
		return c, nil
	default:
		return Unknown{}, nil
	}
}

package backend

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

func writeField(buf *bytes.Buffer, f Field) {
	buf.WriteByte(byte(f))
}

func writeKind(buf *bytes.Buffer, k Kind) {
	buf.WriteByte(byte(k))
}

func writeTxStatus(buf *bytes.Buffer, s TxStatus) {
	buf.WriteByte(byte(s))
}

func writeInt8(buf *bytes.Buffer, i byte) {
	buf.WriteByte(i)
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

func as[T any](m Message, v *T) (bool, error) {
	value, err := m.Parse()
	if err != nil {
		return false, err
	}

	var ok bool
	*v, ok = value.(T)

	return ok, nil
}

func TestReadInt8(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		b := []byte{}

		var first int8
		bread, err := readInt8(b, &first)
		require.ErrorIs(t, err, ErrShortRead)
		require.Equal(t, 0, bread)
	})

	t.Run("one", func(t *testing.T) {
		b := []byte{byte(1)}

		var first int8
		bread, err := readInt8(b, &first)
		require.NoError(t, err)
		require.Equal(t, 1, bread)
		require.Equal(t, int8(1), first)
	})

	t.Run("two", func(t *testing.T) {
		b := []byte{byte(1), byte(2)}

		var first int8
		bread, err := readInt8(b, &first)
		require.NoError(t, err)
		require.Equal(t, 1, bread)
		require.Equal(t, int8(1), first)

		b = b[bread:]

		var second int8
		bread, err = readInt8(b, &second)
		require.NoError(t, err)
		require.Equal(t, 1, bread)
		require.Equal(t, int8(2), second)
	})
}

func TestReadString(t *testing.T) {
	t.Run("iterative", func(t *testing.T) {
		b := []byte{'a', 'b', 'c', '\x00', 'd', 'e', 'f', '\x00', 'g', 'h', 'i'}

		var first string
		bread, err := readString(b, &first)
		require.NoError(t, err)
		require.Equal(t, 4, bread)
		require.Equal(t, "abc", first)

		b = b[bread:]

		var second string
		bread, err = readString(b, &second)
		require.NoError(t, err)
		require.Equal(t, 4, bread)
		require.Equal(t, "def", second)

		b = b[bread:]

		var third string
		bread, err = readString(b, &third)
		require.ErrorIs(t, err, ErrShortRead)
		require.Equal(t, 0, bread)
		require.Equal(t, "", third)
	})

	t.Run("last_character_null", func(t *testing.T) {
		b := []byte{'a', 'b', 'c', '\x00'}

		var first string
		bread, err := readString(b, &first)
		require.NoError(t, err)
		require.Equal(t, 4, bread)
		require.Equal(t, "abc", first)
	})

	t.Run("only_character_null", func(t *testing.T) {
		b := []byte{'\x00'}

		var first string
		bread, err := readString(b, &first)
		require.NoError(t, err)
		require.Equal(t, 1, bread)
		require.Equal(t, "", first)
	})
}

func TestUnmarshalMessage(t *testing.T) {
	var buf bytes.Buffer

	writeKind(&buf, KindAuthentication)
	writeInt32(&buf, 8)
	writeInt32(&buf, 0)

	var m Message

	err := m.Unmarshal(&buf)
	require.NoError(t, err)

	require.Equal(t, KindAuthentication, m.kind)

	expected := make([]byte, 4)
	binary.BigEndian.PutUint32(expected, 0)
	require.Equal(t, expected, m.body)
}

func TestParseMessage(t *testing.T) {
	t.Run("AuthenticationOk", func(t *testing.T) {
		var buf bytes.Buffer

		writeInt32(&buf, 0)

		var m Message
		m.kind = KindAuthentication
		m.body = buf.Bytes()

		var result AuthenticationOk

		ok, err := as(m, &result)
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("AuthenticationKerberosV5", func(t *testing.T) {
		var buf bytes.Buffer

		writeInt32(&buf, 2)

		var m Message
		m.kind = KindAuthentication
		m.body = buf.Bytes()

		var result AuthenticationKerberosV5

		ok, err := as(m, &result)
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("AuthenticationCleartextPassword", func(t *testing.T) {
		var buf bytes.Buffer

		writeInt32(&buf, 3)

		var m Message
		m.kind = KindAuthentication
		m.body = buf.Bytes()

		var result AuthenticationCleartextPassword

		ok, err := as(m, &result)
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("AuthenticationMD5Password", func(t *testing.T) {
		var buf bytes.Buffer

		writeInt32(&buf, 5)              // authentication indicator
		writeBytes(&buf, []byte("abcd")) // salt

		var m Message
		m.kind = KindAuthentication
		m.body = buf.Bytes()

		var result AuthenticationMD5Password

		ok, err := as(m, &result)
		require.NoError(t, err)
		require.True(t, ok)

		require.Equal(t, [4]byte{'a', 'b', 'c', 'd'}, result.Salt)
	})

	t.Run("AuthenticationGSS", func(t *testing.T) {
		var buf bytes.Buffer

		writeInt32(&buf, 7)

		var m Message
		m.kind = KindAuthentication
		m.body = buf.Bytes()

		var result AuthenticationGSS

		ok, err := as(m, &result)
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("AuthenticationGSSContinue", func(t *testing.T) {
		var buf bytes.Buffer

		writeInt32(&buf, 8)
		writeBytes(&buf, []byte("hello"))

		var m Message
		m.kind = KindAuthentication
		m.body = buf.Bytes()

		var result AuthenticationGSSContinue

		ok, err := as(m, &result)
		require.NoError(t, err)
		require.True(t, ok)

		require.Equal(t, []byte("hello"), result.Data)
	})

	t.Run("AuthenticationSSPI", func(t *testing.T) {
		var buf bytes.Buffer

		writeInt32(&buf, 9)

		var m Message
		m.kind = KindAuthentication
		m.body = buf.Bytes()

		var result AuthenticationSSPI

		ok, err := as(m, &result)
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("AuthenticationSASL", func(t *testing.T) {
		var buf bytes.Buffer

		writeInt32(&buf, 10)
		writeString(&buf, "one")
		writeString(&buf, "two")
		writeString(&buf, "three")

		var m Message
		m.kind = KindAuthentication
		m.body = buf.Bytes()

		var result AuthenticationSASL

		ok, err := as(m, &result)
		require.NoError(t, err)
		require.True(t, ok)

		require.Equal(t, []string{"one", "two", "three"}, result.Mechanisms)
	})

	t.Run("AuthenticationSASLContinue", func(t *testing.T) {
		var buf bytes.Buffer

		writeInt32(&buf, 11)
		writeBytes(&buf, []byte("hello"))

		var m Message
		m.kind = KindAuthentication
		m.body = buf.Bytes()

		var result AuthenticationSASLContinue

		ok, err := as(m, &result)
		require.NoError(t, err)
		require.True(t, ok)

		require.Equal(t, []byte("hello"), result.Data)
	})

	t.Run("AuthenticationSASLFinal", func(t *testing.T) {
		var buf bytes.Buffer

		writeInt32(&buf, 12)
		writeBytes(&buf, []byte("hello"))

		var m Message
		m.kind = KindAuthentication
		m.body = buf.Bytes()

		var result AuthenticationSASLFinal

		ok, err := as(m, &result)
		require.NoError(t, err)
		require.True(t, ok)

		require.Equal(t, []byte("hello"), result.Data)
	})

	t.Run("BackendKeyData", func(t *testing.T) {
		var buf bytes.Buffer

		writeInt32(&buf, 111)
		writeBytes(&buf, []byte("hello"))

		var m Message
		m.kind = KindKeyData
		m.body = buf.Bytes()

		var result BackendKeyData

		ok, err := as(m, &result)
		require.NoError(t, err)
		require.True(t, ok)

		require.Equal(t, int32(111), result.ProcessID)
		require.Equal(t, []byte("hello"), result.SecretKey)
	})

	t.Run("BindComplete", func(t *testing.T) {
		var m Message
		m.kind = KindBindComplete
		m.body = []byte{}

		var result BindComplete

		ok, err := as(m, &result)
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("CloseComplete", func(t *testing.T) {
		var m Message
		m.kind = KindCloseComplete
		m.body = []byte{}

		var result CloseComplete

		ok, err := as(m, &result)
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("CommandComplete", func(t *testing.T) {
		var buf bytes.Buffer

		writeString(&buf, "INSERT 11 11")

		var m Message
		m.kind = KindCommandComplete
		m.body = buf.Bytes()

		var result CommandComplete

		ok, err := as(m, &result)
		require.NoError(t, err)
		require.True(t, ok)

		require.Equal(t, "INSERT 11 11", result.Tag)
	})

	t.Run("CopyData", func(t *testing.T) {
		var buf bytes.Buffer

		writeBytes(&buf, []byte("hello"))

		var m Message
		m.kind = KindCopyData
		m.body = buf.Bytes()

		var result CopyData

		ok, err := as(m, &result)
		require.NoError(t, err)
		require.True(t, ok)

		require.Equal(t, []byte("hello"), result.Data)
	})

	t.Run("CopyDone", func(t *testing.T) {
		var m Message
		m.kind = KindCopyDone
		m.body = []byte{}

		var result CopyDone

		ok, err := as(m, &result)
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("CopyInResponse", func(t *testing.T) {
		var buf bytes.Buffer

		writeInt8(&buf, 1)
		writeInt16(&buf, 2)
		writeInt16(&buf, int16(FormatBinary))
		writeInt16(&buf, int16(FormatBinary))

		var m Message
		m.kind = KindCopyInResponse
		m.body = buf.Bytes()

		var result CopyInResponse

		ok, err := as(m, &result)
		require.NoError(t, err)
		require.True(t, ok)

		require.Equal(t, FormatBinary, result.Format)
		require.Equal(t, []Format{FormatBinary, FormatBinary}, result.Columns)
	})

	t.Run("CopyOutResponse", func(t *testing.T) {
		var buf bytes.Buffer

		writeInt8(&buf, 1)
		writeInt16(&buf, 2)
		writeInt16(&buf, int16(FormatBinary))
		writeInt16(&buf, int16(FormatBinary))

		var m Message
		m.kind = KindCopyOutResponse
		m.body = buf.Bytes()

		var result CopyOutResponse

		ok, err := as(m, &result)
		require.NoError(t, err)
		require.True(t, ok)

		require.Equal(t, FormatBinary, result.Format)
		require.Equal(t, []Format{FormatBinary, FormatBinary}, result.Columns)
	})

	t.Run("CopyBothResponse", func(t *testing.T) {
		var buf bytes.Buffer

		writeInt8(&buf, 1)
		writeInt16(&buf, 2)
		writeInt16(&buf, int16(FormatBinary))
		writeInt16(&buf, int16(FormatBinary))

		var m Message
		m.kind = KindCopyBothResponse
		m.body = buf.Bytes()

		var result CopyBothResponse

		ok, err := as(m, &result)
		require.NoError(t, err)
		require.True(t, ok)

		require.Equal(t, FormatBinary, result.Format)
		require.Equal(t, []Format{FormatBinary, FormatBinary}, result.Columns)
	})

	t.Run("DataRow", func(t *testing.T) {
		var buf bytes.Buffer

		writeInt16(&buf, 4)
		writeInt32(&buf, 5)
		writeBytes(&buf, []byte("hello"))
		writeInt32(&buf, -1)
		writeInt32(&buf, 0)
		writeInt32(&buf, 5)
		writeBytes(&buf, []byte("world"))

		var m Message
		m.kind = KindDataRow
		m.body = buf.Bytes()

		var result DataRow

		ok, err := as(m, &result)
		require.NoError(t, err)
		require.True(t, ok)

		require.Equal(t, [][]byte{
			[]byte("hello"),
			[]byte(nil),
			[]byte{},
			[]byte("world"),
		}, result.Columns)
	})

	t.Run("EmptyQueryResponse", func(t *testing.T) {
		var m Message
		m.kind = KindEmptyQueryResponse
		m.body = []byte{}

		var result EmptyQueryResponse

		ok, err := as(m, &result)
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("ErrorResponse", func(t *testing.T) {
		var buf bytes.Buffer

		writeField(&buf, FieldSeverity)
		writeString(&buf, "ERROR")
		writeField(&buf, FieldMessage)
		writeString(&buf, "hello world")
		writeInt8(&buf, 0)

		var m Message
		m.kind = KindErrorResponse
		m.body = buf.Bytes()

		var result ErrorResponse

		ok, err := as(m, &result)
		require.NoError(t, err)
		require.True(t, ok)

		require.Equal(t, []Field{FieldSeverity, FieldMessage}, result.Fields)
		require.Equal(t, []string{"ERROR", "hello world"}, result.Values)
	})

	t.Run("FunctionCallResponse", func(t *testing.T) {
		var buf bytes.Buffer

		writeInt32(&buf, 11)                    // length of function response data
		writeBytes(&buf, []byte("hello world")) // function response data

		var m Message
		m.kind = KindFunctionCallResponse
		m.body = buf.Bytes()

		var result FunctionCallResponse

		ok, err := as(m, &result)
		require.NoError(t, err)
		require.True(t, ok)

		require.Equal(t, []byte("hello world"), result.Result)
	})

	t.Run("NegotiateProtocolVersion", func(t *testing.T) {
		var buf bytes.Buffer

		writeInt32(&buf, 111)      // newest supported minor version
		writeInt32(&buf, 2)        // number of unrecognized protocols
		writeString(&buf, "hello") // first unrecognized protocol
		writeString(&buf, "world") // second unrecognized protocol

		var m Message
		m.kind = KindNegotiateProtocolVersion
		m.body = buf.Bytes()

		var result NegotiateProtocolVersion

		ok, err := as(m, &result)
		require.NoError(t, err)
		require.True(t, ok)

		require.Equal(t, int32(111), result.MinorVersionSupported)
		require.Equal(t, []string{"hello", "world"}, result.UnrecognizedOptions)
	})

	t.Run("NoData", func(t *testing.T) {
		var m Message
		m.kind = KindNoData
		m.body = []byte{}

		var result NoData

		ok, err := as(m, &result)
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("NoticeResponse", func(t *testing.T) {
		var buf bytes.Buffer

		writeField(&buf, FieldSeverity)
		writeString(&buf, "WARNING")
		writeField(&buf, FieldMessage)
		writeString(&buf, "hello world")
		writeInt8(&buf, 0)

		var m Message
		m.kind = KindNoticeResponse
		m.body = buf.Bytes()

		var result NoticeResponse

		ok, err := as(m, &result)
		require.NoError(t, err)
		require.True(t, ok)

		require.Equal(t, []Field{FieldSeverity, FieldMessage}, result.Fields)
		require.Equal(t, []string{"WARNING", "hello world"}, result.Values)
	})

	t.Run("NotificationResponse", func(t *testing.T) {
		var buf bytes.Buffer

		writeInt32(&buf, 111)
		writeString(&buf, "hello")
		writeString(&buf, "world")

		var m Message
		m.kind = KindNotificationResponse
		m.body = buf.Bytes()

		var result NotificationResponse

		ok, err := as(m, &result)
		require.NoError(t, err)
		require.True(t, ok)

		require.Equal(t, int32(111), result.ProcessID)
		require.Equal(t, "hello", result.Channel)
		require.Equal(t, "world", result.Payload)
	})

	t.Run("ParameterDescription", func(t *testing.T) {
		var buf bytes.Buffer

		writeInt16(&buf, 2)
		writeInt32(&buf, 1)
		writeInt32(&buf, 2)

		var m Message
		m.kind = KindParameterDescription
		m.body = buf.Bytes()

		var result ParameterDescription

		ok, err := as(m, &result)
		require.NoError(t, err)
		require.True(t, ok)

		require.Len(t, result.Parameters, 2)
		require.Equal(t, int32(1), result.Parameters[0])
		require.Equal(t, int32(2), result.Parameters[1])
	})

	t.Run("ParameterStatus", func(t *testing.T) {
		var buf bytes.Buffer

		writeString(&buf, "hello")
		writeString(&buf, "world")

		var m Message
		m.kind = KindParameterStatus
		m.body = buf.Bytes()

		var result ParameterStatus

		ok, err := as(m, &result)
		require.NoError(t, err)
		require.True(t, ok)

		require.Equal(t, "hello", result.Name)
		require.Equal(t, "world", result.Value)
	})

	t.Run("ParseComplete", func(t *testing.T) {
		var m Message
		m.kind = KindParseComplete
		m.body = []byte{}

		var result ParseComplete

		ok, err := as(m, &result)
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("PortalSuspended", func(t *testing.T) {
		var m Message
		m.kind = KindPortalSuspended
		m.body = []byte{}

		var result PortalSuspended

		ok, err := as(m, &result)
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("ReadyForQuery", func(t *testing.T) {
		var buf bytes.Buffer

		writeTxStatus(&buf, TxStatusActive)

		var m Message
		m.kind = KindReadyForQuery
		m.body = buf.Bytes()

		var result ReadyForQuery

		ok, err := as(m, &result)
		require.NoError(t, err)
		require.True(t, ok)

		require.Equal(t, TxStatusActive, result.TxStatus)
	})
}

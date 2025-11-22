package backend

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

func as[T any](m xMessage, v *T) (bool, error) {
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
		require.ErrorIs(t, err, ErrValueUnderflow)
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
		require.ErrorIs(t, err, ErrValueUnderflow)
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

func TestReadMessage(t *testing.T) {
	var buf bytes.Buffer

	writeKind(&buf, KindAuthentication)
	writeInt32(&buf, 8)
	writeInt32(&buf, 0)

	var m xMessage

	err := ReadMessage(&buf, &m)
	require.NoError(t, err)

	require.Equal(t, KindAuthentication, m.kind)

	expected := make([]byte, 4)
	binary.BigEndian.PutUint32(expected, 0)
	require.Equal(t, expected, m.data)
}

func TestParseMessage(t *testing.T) {
	t.Run("EncodeAuthenticationOk", func(t *testing.T) {
		var expected bytes.Buffer

		writeKind(&expected, KindAuthentication)
		writeInt32(&expected, 8)
		writeInt32(&expected, 0)

		var msg AuthenticationOk

		var buf bytes.Buffer
		err := Write(&buf, &msg)
		require.NoError(t, err)

		require.Equal(t, expected.Bytes(), buf.Bytes())
	})

	t.Run("DecodeAuthenticationOk", func(t *testing.T) {
		var buf bytes.Buffer

		writeInt32(&buf, 0)

		var m xMessage
		m.kind = KindAuthentication
		m.data = buf.Bytes()

		var result AuthenticationOk

		ok, err := as(m, &result)
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("AuthenticationKerberosV5", func(t *testing.T) {
		var buf bytes.Buffer

		writeInt32(&buf, 2)

		var m xMessage
		m.kind = KindAuthentication
		m.data = buf.Bytes()

		var result AuthenticationKerberosV5

		ok, err := as(m, &result)
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("AuthenticationCleartextPassword", func(t *testing.T) {
		var buf bytes.Buffer

		writeInt32(&buf, 3)

		var m xMessage
		m.kind = KindAuthentication
		m.data = buf.Bytes()

		var result AuthenticationCleartextPassword

		ok, err := as(m, &result)
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("AuthenticationMD5Password", func(t *testing.T) {
		var buf bytes.Buffer

		writeInt32(&buf, 5)              // authentication indicator
		writeBytes(&buf, []byte("abcd")) // salt

		var m xMessage
		m.kind = KindAuthentication
		m.data = buf.Bytes()

		var result AuthenticationMD5Password

		ok, err := as(m, &result)
		require.NoError(t, err)
		require.True(t, ok)

		require.Equal(t, [4]byte{'a', 'b', 'c', 'd'}, result.Salt)
	})

	t.Run("AuthenticationGSS", func(t *testing.T) {
		var buf bytes.Buffer

		writeInt32(&buf, 7)

		var m xMessage
		m.kind = KindAuthentication
		m.data = buf.Bytes()

		var result AuthenticationGSS

		ok, err := as(m, &result)
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("AuthenticationGSSContinue", func(t *testing.T) {
		var buf bytes.Buffer

		writeInt32(&buf, 8)
		writeBytes(&buf, []byte("hello"))

		var m xMessage
		m.kind = KindAuthentication
		m.data = buf.Bytes()

		var result AuthenticationGSSContinue

		ok, err := as(m, &result)
		require.NoError(t, err)
		require.True(t, ok)

		require.Equal(t, []byte("hello"), result.Data)
	})

	t.Run("AuthenticationSSPI", func(t *testing.T) {
		var buf bytes.Buffer

		writeInt32(&buf, 9)

		var m xMessage
		m.kind = KindAuthentication
		m.data = buf.Bytes()

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

		var m xMessage
		m.kind = KindAuthentication
		m.data = buf.Bytes()

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

		var m xMessage
		m.kind = KindAuthentication
		m.data = buf.Bytes()

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

		var m xMessage
		m.kind = KindAuthentication
		m.data = buf.Bytes()

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

		var m xMessage
		m.kind = KindKeyData
		m.data = buf.Bytes()

		var result BackendKeyData

		ok, err := as(m, &result)
		require.NoError(t, err)
		require.True(t, ok)

		require.Equal(t, int32(111), result.ProcessID)
		require.Equal(t, []byte("hello"), result.SecretKey)
	})

	t.Run("BindComplete", func(t *testing.T) {
		var m xMessage
		m.kind = KindBindComplete
		m.data = []byte{}

		var result BindComplete

		ok, err := as(m, &result)
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("CloseComplete", func(t *testing.T) {
		var m xMessage
		m.kind = KindCloseComplete
		m.data = []byte{}

		var result CloseComplete

		ok, err := as(m, &result)
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("CommandComplete", func(t *testing.T) {
		var buf bytes.Buffer

		writeString(&buf, "INSERT 11 11")

		var m xMessage
		m.kind = KindCommandComplete
		m.data = buf.Bytes()

		var result CommandComplete

		ok, err := as(m, &result)
		require.NoError(t, err)
		require.True(t, ok)

		require.Equal(t, "INSERT 11 11", result.Tag)
	})

	t.Run("CopyData", func(t *testing.T) {
		var buf bytes.Buffer

		writeBytes(&buf, []byte("hello"))

		var m xMessage
		m.kind = KindCopyData
		m.data = buf.Bytes()

		var result CopyData

		ok, err := as(m, &result)
		require.NoError(t, err)
		require.True(t, ok)

		require.Equal(t, []byte("hello"), result.Data)
	})

	t.Run("CopyDone", func(t *testing.T) {
		var m xMessage
		m.kind = KindCopyDone
		m.data = []byte{}

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

		var m xMessage
		m.kind = KindCopyInResponse
		m.data = buf.Bytes()

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

		var m xMessage
		m.kind = KindCopyOutResponse
		m.data = buf.Bytes()

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

		var m xMessage
		m.kind = KindCopyBothResponse
		m.data = buf.Bytes()

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

		var m xMessage
		m.kind = KindDataRow
		m.data = buf.Bytes()

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
		var m xMessage
		m.kind = KindEmptyQueryResponse
		m.data = []byte{}

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

		var m xMessage
		m.kind = KindErrorResponse
		m.data = buf.Bytes()

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

		var m xMessage
		m.kind = KindFunctionCallResponse
		m.data = buf.Bytes()

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

		var m xMessage
		m.kind = KindNegotiateProtocolVersion
		m.data = buf.Bytes()

		var result NegotiateProtocolVersion

		ok, err := as(m, &result)
		require.NoError(t, err)
		require.True(t, ok)

		require.Equal(t, int32(111), result.MinorVersionSupported)
		require.Equal(t, []string{"hello", "world"}, result.UnrecognizedOptions)
	})

	t.Run("NoData", func(t *testing.T) {
		var m xMessage
		m.kind = KindNoData
		m.data = []byte{}

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

		var m xMessage
		m.kind = KindNoticeResponse
		m.data = buf.Bytes()

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

		var m xMessage
		m.kind = KindNotificationResponse
		m.data = buf.Bytes()

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

		var m xMessage
		m.kind = KindParameterDescription
		m.data = buf.Bytes()

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

		var m xMessage
		m.kind = KindParameterStatus
		m.data = buf.Bytes()

		var result ParameterStatus

		ok, err := as(m, &result)
		require.NoError(t, err)
		require.True(t, ok)

		require.Equal(t, "hello", result.Name)
		require.Equal(t, "world", result.Value)
	})

	t.Run("ParseComplete", func(t *testing.T) {
		var m xMessage
		m.kind = KindParseComplete
		m.data = []byte{}

		var result ParseComplete

		ok, err := as(m, &result)
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("PortalSuspended", func(t *testing.T) {
		var m xMessage
		m.kind = KindPortalSuspended
		m.data = []byte{}

		var result PortalSuspended

		ok, err := as(m, &result)
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("ReadyForQuery", func(t *testing.T) {
		var buf bytes.Buffer

		writeTxStatus(&buf, TxStatusActive)

		var m xMessage
		m.kind = KindReadyForQuery
		m.data = buf.Bytes()

		var result ReadyForQuery

		ok, err := as(m, &result)
		require.NoError(t, err)
		require.True(t, ok)

		require.Equal(t, TxStatusActive, result.TxStatus)
	})

	t.Run("RowDescription", func(t *testing.T) {
		var buf bytes.Buffer

		writeInt16(&buf, 2)

		writeString(&buf, "hello")
		writeInt32(&buf, 101)
		writeInt16(&buf, 102)
		writeInt32(&buf, 103)
		writeInt16(&buf, 104)
		writeInt32(&buf, 105)
		writeFormat(&buf, FormatBinary)

		writeString(&buf, "world")
		writeInt32(&buf, 201)
		writeInt16(&buf, 202)
		writeInt32(&buf, 203)
		writeInt16(&buf, 204)
		writeInt32(&buf, 205)
		writeFormat(&buf, FormatBinary)

		var m xMessage
		m.kind = KindRowDescription
		m.data = buf.Bytes()

		var result RowDescription

		ok, err := as(m, &result)
		require.NoError(t, err)
		require.True(t, ok)

		require.Equal(t, []string{"hello", "world"}, result.Names)
		require.Equal(t, []int32{101, 201}, result.Tables)
		require.Equal(t, []int16{102, 202}, result.Columns)
		require.Equal(t, []int32{103, 203}, result.DataTypes)
		require.Equal(t, []int16{104, 204}, result.Sizes)
		require.Equal(t, []int32{105, 205}, result.Modifiers)
		require.Equal(t, []Format{FormatBinary, FormatBinary}, result.Formats)
	})
}

package backend

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

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

func TestMessage(t *testing.T) {
	t.Run("AuthenticationOk", func(t *testing.T) {
		var data bytes.Buffer
		writeByte(&data, msgKindAuthentication)
		writeInt32(&data, 8)
		writeInt32(&data, authKindOk)

		t.Run("Write", func(t *testing.T) {
			var msg AuthenticationOk

			var buf bytes.Buffer
			err := Write(&buf, &msg)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(AuthenticationOk)
			require.True(t, ok)

			var expected AuthenticationOk

			require.Equal(t, expected, m)
		})
	})

	t.Run("AuthenticationKerberosV5", func(t *testing.T) {
		var data bytes.Buffer
		writeByte(&data, msgKindAuthentication)
		writeInt32(&data, 8)
		writeInt32(&data, authKindKerberosV5)

		t.Run("Write", func(t *testing.T) {
			var msg AuthenticationKerberosV5

			var buf bytes.Buffer
			err := Write(&buf, &msg)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(AuthenticationKerberosV5)
			require.True(t, ok)

			var expected AuthenticationKerberosV5

			require.Equal(t, expected, m)
		})
	})

	t.Run("AuthenticationCleartextPassword", func(t *testing.T) {
		var data bytes.Buffer
		writeByte(&data, msgKindAuthentication)
		writeInt32(&data, 8)
		writeInt32(&data, authKindCleartextPassword)

		t.Run("Write", func(t *testing.T) {
			var msg AuthenticationCleartextPassword

			var buf bytes.Buffer
			err := Write(&buf, &msg)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(AuthenticationCleartextPassword)
			require.True(t, ok)

			var expected AuthenticationCleartextPassword

			require.Equal(t, expected, m)
		})
	})

	t.Run("AuthenticationMD5Password", func(t *testing.T) {
		var data bytes.Buffer
		writeByte(&data, msgKindAuthentication)
		writeInt32(&data, 12)
		writeInt32(&data, authKindMD5Password)
		writeBytes(&data, []byte("abcd"))

		t.Run("Write", func(t *testing.T) {
			var msg AuthenticationMD5Password
			msg.Salt = [4]byte{'a', 'b', 'c', 'd'}

			var buf bytes.Buffer
			err := Write(&buf, &msg)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(AuthenticationMD5Password)
			require.True(t, ok)

			var expected AuthenticationMD5Password
			expected.Salt = [4]byte{'a', 'b', 'c', 'd'}

			require.Equal(t, expected, m)
		})
	})

	t.Run("AuthenticationGSS", func(t *testing.T) {
		var data bytes.Buffer
		writeByte(&data, msgKindAuthentication)
		writeInt32(&data, 8)
		writeInt32(&data, authKindGSS)

		t.Run("Write", func(t *testing.T) {
			var msg AuthenticationGSS

			var buf bytes.Buffer
			err := Write(&buf, &msg)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(AuthenticationGSS)
			require.True(t, ok)

			var expected AuthenticationGSS

			require.Equal(t, expected, m)
		})
	})

	t.Run("AuthenticationGSSContinue", func(t *testing.T) {
		var data bytes.Buffer
		writeByte(&data, msgKindAuthentication)
		writeInt32(&data, 13)
		writeInt32(&data, authKindGSSContinue)
		writeBytes(&data, []byte("hello"))

		t.Run("Write", func(t *testing.T) {
			var msg AuthenticationGSSContinue
			msg.Data = []byte("hello")

			var buf bytes.Buffer
			err := Write(&buf, &msg)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(AuthenticationGSSContinue)
			require.True(t, ok)

			var expected AuthenticationGSSContinue
			expected.Data = []byte("hello")

			require.Equal(t, expected, m)
		})
	})

	t.Run("AuthenticationSSPI", func(t *testing.T) {
		var data bytes.Buffer
		writeByte(&data, msgKindAuthentication)
		writeInt32(&data, 8)
		writeInt32(&data, authKindSSPI)

		t.Run("Write", func(t *testing.T) {
			var msg AuthenticationSSPI

			var buf bytes.Buffer
			err := Write(&buf, &msg)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(AuthenticationSSPI)
			require.True(t, ok)

			var expected AuthenticationSSPI

			require.Equal(t, expected, m)
		})
	})

	t.Run("AuthenticationSASL", func(t *testing.T) {
		var data bytes.Buffer
		writeByte(&data, msgKindAuthentication)
		writeInt32(&data, 21)
		writeInt32(&data, authKindSASL)
		writeString(&data, "one")
		writeString(&data, "two")
		writeString(&data, "three")

		t.Run("Write", func(t *testing.T) {
			var msg AuthenticationSASL
			msg.Mechanisms = []string{"one", "two", "three"}

			var buf bytes.Buffer
			err := Write(&buf, &msg)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(AuthenticationSASL)
			require.True(t, ok)

			var expected AuthenticationSASL
			expected.Mechanisms = []string{"one", "two", "three"}

			require.Equal(t, expected, m)
		})
	})

	t.Run("AuthenticationSASLContinue", func(t *testing.T) {
		var data bytes.Buffer
		writeByte(&data, msgKindAuthentication)
		writeInt32(&data, 13)
		writeInt32(&data, authKindSASLContinue)
		writeBytes(&data, []byte("hello"))

		t.Run("Write", func(t *testing.T) {
			var msg AuthenticationSASLContinue
			msg.Data = []byte("hello")

			var buf bytes.Buffer
			err := Write(&buf, &msg)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(AuthenticationSASLContinue)
			require.True(t, ok)

			var expected AuthenticationSASLContinue
			expected.Data = []byte("hello")

			require.Equal(t, expected, m)
		})
	})

	t.Run("AuthenticationSASLFinal", func(t *testing.T) {
		var data bytes.Buffer
		writeByte(&data, msgKindAuthentication)
		writeInt32(&data, 13)
		writeInt32(&data, authKindSASLFinal)
		writeBytes(&data, []byte("hello"))

		t.Run("Write", func(t *testing.T) {
			var msg AuthenticationSASLFinal
			msg.Data = []byte("hello")

			var buf bytes.Buffer
			err := Write(&buf, &msg)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(AuthenticationSASLFinal)
			require.True(t, ok)

			var expected AuthenticationSASLFinal
			expected.Data = []byte("hello")

			require.Equal(t, expected, m)
		})
	})

	t.Run("BackendKeyData", func(t *testing.T) {
		var data bytes.Buffer
		writeByte(&data, msgKindKeyData)
		writeInt32(&data, 13)
		writeInt32(&data, 111)
		writeBytes(&data, []byte("hello"))

		t.Run("Write", func(t *testing.T) {
			var msg BackendKeyData
			msg.ProcessID = 111
			msg.SecretKey = []byte("hello")

			var buf bytes.Buffer
			err := Write(&buf, &msg)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(BackendKeyData)
			require.True(t, ok)

			var expected BackendKeyData
			expected.ProcessID = 111
			expected.SecretKey = []byte("hello")

			require.Equal(t, expected, m)
		})
	})

	t.Run("BindComplete", func(t *testing.T) {
		var data bytes.Buffer
		writeByte(&data, msgKindBindComplete)
		writeInt32(&data, 4)

		t.Run("Write", func(t *testing.T) {
			var msg BindComplete

			var buf bytes.Buffer
			err := Write(&buf, &msg)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(BindComplete)
			require.True(t, ok)

			var expected BindComplete

			require.Equal(t, expected, m)
		})
	})

	t.Run("CloseComplete", func(t *testing.T) {
		var data bytes.Buffer
		writeByte(&data, msgKindCloseComplete)
		writeInt32(&data, 4)

		t.Run("Write", func(t *testing.T) {
			var msg CloseComplete

			var buf bytes.Buffer
			err := Write(&buf, &msg)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(CloseComplete)
			require.True(t, ok)

			var expected CloseComplete

			require.Equal(t, expected, m)
		})
	})

	t.Run("CommandComplete", func(t *testing.T) {
		var data bytes.Buffer
		writeByte(&data, msgKindCommandComplete)
		writeInt32(&data, 17)
		writeString(&data, "INSERT 11 11")

		t.Run("Write", func(t *testing.T) {
			var msg CommandComplete
			msg.Tag = "INSERT 11 11"

			var buf bytes.Buffer
			err := Write(&buf, &msg)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(CommandComplete)
			require.True(t, ok)

			var expected CommandComplete
			expected.Tag = "INSERT 11 11"

			require.Equal(t, expected, m)
		})
	})

	t.Run("CopyData", func(t *testing.T) {
		var data bytes.Buffer
		writeByte(&data, msgKindCopyData)
		writeInt32(&data, 9)
		writeBytes(&data, []byte("hello"))

		t.Run("Write", func(t *testing.T) {
			var msg CopyData
			msg.Data = []byte("hello")

			var buf bytes.Buffer
			err := Write(&buf, &msg)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(CopyData)
			require.True(t, ok)

			var expected CopyData
			expected.Data = []byte("hello")

			require.Equal(t, expected, m)
		})
	})

	t.Run("CopyDone", func(t *testing.T) {
		var data bytes.Buffer
		writeByte(&data, msgKindCopyDone)
		writeInt32(&data, 4)

		t.Run("Write", func(t *testing.T) {
			var msg CopyDone

			var buf bytes.Buffer
			err := Write(&buf, &msg)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(CopyDone)
			require.True(t, ok)

			var expected CopyDone

			require.Equal(t, expected, m)
		})
	})

	t.Run("CopyInResponse", func(t *testing.T) {
		var data bytes.Buffer
		writeByte(&data, msgKindCopyInResponse)
		writeInt32(&data, 11)
		writeInt8(&data, FormatBinary)
		writeInt16(&data, 2)
		writeInt16(&data, int16(FormatBinary))
		writeInt16(&data, int16(FormatBinary))
		var buf bytes.Buffer

		writeByte(&buf, 1)
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

		writeByte(&buf, 1)
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

		writeByte(&buf, 1)
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
		writeByte(&buf, 0)

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
		writeByte(&buf, 0)

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

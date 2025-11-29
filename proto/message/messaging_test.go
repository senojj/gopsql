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

		var msg AuthenticationOk

		t.Run("Write", func(t *testing.T) {
			var buf bytes.Buffer
			err := msg.Encode(&buf)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(*AuthenticationOk)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("AuthenticationKerberosV5", func(t *testing.T) {
		var data bytes.Buffer
		writeByte(&data, msgKindAuthentication)
		writeInt32(&data, 8)
		writeInt32(&data, authKindKerberosV5)

		var msg AuthenticationKerberosV5

		t.Run("Write", func(t *testing.T) {
			var buf bytes.Buffer
			err := msg.Encode(&buf)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(*AuthenticationKerberosV5)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("AuthenticationCleartextPassword", func(t *testing.T) {
		var data bytes.Buffer
		writeByte(&data, msgKindAuthentication)
		writeInt32(&data, 8)
		writeInt32(&data, authKindCleartextPassword)

		var msg AuthenticationCleartextPassword

		t.Run("Write", func(t *testing.T) {
			var buf bytes.Buffer
			err := msg.Encode(&buf)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(*AuthenticationCleartextPassword)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("AuthenticationMD5Password", func(t *testing.T) {
		var data bytes.Buffer
		writeByte(&data, msgKindAuthentication)
		writeInt32(&data, 12)
		writeInt32(&data, authKindMD5Password)
		writeBytes(&data, []byte("abcd"))

		var msg AuthenticationMD5Password
		msg.Salt = [4]byte{'a', 'b', 'c', 'd'}

		t.Run("Write", func(t *testing.T) {
			var buf bytes.Buffer
			err := msg.Encode(&buf)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(*AuthenticationMD5Password)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("AuthenticationGSS", func(t *testing.T) {
		var data bytes.Buffer
		writeByte(&data, msgKindAuthentication)
		writeInt32(&data, 8)
		writeInt32(&data, authKindGSS)

		var msg AuthenticationGSS

		t.Run("Write", func(t *testing.T) {
			var buf bytes.Buffer
			err := msg.Encode(&buf)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(*AuthenticationGSS)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("AuthenticationGSSContinue", func(t *testing.T) {
		var data bytes.Buffer
		writeByte(&data, msgKindAuthentication)
		writeInt32(&data, 13)
		writeInt32(&data, authKindGSSContinue)
		writeBytes(&data, []byte("hello"))

		var msg AuthenticationGSSContinue
		msg.Data = []byte("hello")

		t.Run("Write", func(t *testing.T) {
			var buf bytes.Buffer
			err := msg.Encode(&buf)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(*AuthenticationGSSContinue)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("AuthenticationSSPI", func(t *testing.T) {
		var data bytes.Buffer
		writeByte(&data, msgKindAuthentication)
		writeInt32(&data, 8)
		writeInt32(&data, authKindSSPI)

		var msg AuthenticationSSPI

		t.Run("Write", func(t *testing.T) {
			var buf bytes.Buffer
			err := msg.Encode(&buf)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(*AuthenticationSSPI)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("AuthenticationSASL", func(t *testing.T) {
		var data bytes.Buffer
		writeByte(&data, msgKindAuthentication)
		writeInt32(&data, 23)
		writeInt32(&data, authKindSASL)
		writeString(&data, "one")
		writeString(&data, "two")
		writeString(&data, "three")
		writeByte(&data, 0x0)

		var msg AuthenticationSASL
		msg.Mechanisms = []string{"one", "two", "three"}

		var dataZero bytes.Buffer
		writeByte(&dataZero, msgKindAuthentication)
		writeInt32(&dataZero, 9)
		writeInt32(&dataZero, authKindSASL)
		writeByte(&dataZero, 0x0)

		var msgZero AuthenticationSASL
		msgZero.Mechanisms = []string{}

		t.Run("Write", func(t *testing.T) {
			t.Run("Present", func(t *testing.T) {
				var buf bytes.Buffer
				err := msg.Encode(&buf)
				require.NoError(t, err)

				require.Equal(t, data.Bytes(), buf.Bytes())
			})

			t.Run("Zero", func(t *testing.T) {
				var buf bytes.Buffer
				err := msgZero.Encode(&buf)
				require.NoError(t, err)

				require.Equal(t, dataZero.Bytes(), buf.Bytes())
			})
		})

		t.Run("Read", func(t *testing.T) {
			t.Run("Present", func(t *testing.T) {
				value, err := Read(&data)
				require.NoError(t, err)

				m, ok := value.(*AuthenticationSASL)
				require.True(t, ok)

				require.Equal(t, &msg, m)
			})

			t.Run("Zero", func(t *testing.T) {
				value, err := Read(&dataZero)
				require.NoError(t, err)

				m, ok := value.(*AuthenticationSASL)
				require.True(t, ok)

				require.Equal(t, &msgZero, m)
			})
		})
	})

	t.Run("AuthenticationSASLContinue", func(t *testing.T) {
		var data bytes.Buffer
		writeByte(&data, msgKindAuthentication)
		writeInt32(&data, 13)
		writeInt32(&data, authKindSASLContinue)
		writeBytes(&data, []byte("hello"))

		var msg AuthenticationSASLContinue
		msg.Data = []byte("hello")

		t.Run("Write", func(t *testing.T) {
			var buf bytes.Buffer
			err := msg.Encode(&buf)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(*AuthenticationSASLContinue)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("AuthenticationSASLFinal", func(t *testing.T) {
		var data bytes.Buffer
		writeByte(&data, msgKindAuthentication)
		writeInt32(&data, 13)
		writeInt32(&data, authKindSASLFinal)
		writeBytes(&data, []byte("hello"))

		var msg AuthenticationSASLFinal
		msg.Data = []byte("hello")

		t.Run("Write", func(t *testing.T) {
			var buf bytes.Buffer
			err := msg.Encode(&buf)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(*AuthenticationSASLFinal)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("BackendKeyData", func(t *testing.T) {
		var data bytes.Buffer
		writeByte(&data, msgKindBackendKeyData)
		writeInt32(&data, 13)
		writeInt32(&data, 111)
		writeBytes(&data, []byte("hello"))

		var msg BackendKeyData
		msg.ProcessID = 111
		msg.SecretKey = []byte("hello")

		t.Run("Write", func(t *testing.T) {
			var buf bytes.Buffer
			err := msg.Encode(&buf)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(*BackendKeyData)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("BindComplete", func(t *testing.T) {
		var data bytes.Buffer
		writeByte(&data, msgKindBindComplete)
		writeInt32(&data, 4)

		var msg BindComplete

		t.Run("Write", func(t *testing.T) {
			var buf bytes.Buffer
			err := msg.Encode(&buf)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(*BindComplete)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("CloseComplete", func(t *testing.T) {
		var data bytes.Buffer
		writeByte(&data, msgKindCloseComplete)
		writeInt32(&data, 4)

		var msg CloseComplete

		t.Run("Write", func(t *testing.T) {
			var buf bytes.Buffer
			err := msg.Encode(&buf)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(*CloseComplete)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("CommandComplete", func(t *testing.T) {
		var data bytes.Buffer
		writeByte(&data, msgKindCommandComplete)
		writeInt32(&data, 17)
		writeString(&data, "INSERT 11 11")

		var msg CommandComplete
		msg.Tag = "INSERT 11 11"

		t.Run("Write", func(t *testing.T) {
			var buf bytes.Buffer
			err := msg.Encode(&buf)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(*CommandComplete)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("CopyData", func(t *testing.T) {
		var data bytes.Buffer
		writeByte(&data, msgKindCopyData)
		writeInt32(&data, 9)
		writeBytes(&data, []byte("hello"))

		var msg CopyData
		msg.Data = []byte("hello")

		t.Run("Write", func(t *testing.T) {
			var buf bytes.Buffer
			err := msg.Encode(&buf)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(*CopyData)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("CopyDone", func(t *testing.T) {
		var data bytes.Buffer
		writeByte(&data, msgKindCopyDone)
		writeInt32(&data, 4)

		var msg CopyDone

		t.Run("Write", func(t *testing.T) {
			var buf bytes.Buffer
			err := msg.Encode(&buf)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(*CopyDone)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("CopyInResponse", func(t *testing.T) {
		var data bytes.Buffer
		writeByte(&data, msgKindCopyInResponse)
		writeInt32(&data, 11)
		writeInt8(&data, FormatBinary)
		writeInt16(&data, 2)
		writeInt16(&data, ColumnFormatBinary)
		writeInt16(&data, ColumnFormatBinary)

		var msg CopyInResponse
		msg.Format = FormatBinary
		msg.Columns = make([]int16, 2)
		msg.Columns[0] = ColumnFormatBinary
		msg.Columns[1] = ColumnFormatBinary

		t.Run("Write", func(t *testing.T) {
			var buf bytes.Buffer
			err := msg.Encode(&buf)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(*CopyInResponse)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("CopyOutResponse", func(t *testing.T) {
		var data bytes.Buffer
		writeByte(&data, msgKindCopyOutResponse)
		writeInt32(&data, 11)
		writeInt8(&data, FormatBinary)
		writeInt16(&data, 2)
		writeInt16(&data, ColumnFormatBinary)
		writeInt16(&data, ColumnFormatBinary)

		var msg CopyOutResponse
		msg.Format = FormatBinary
		msg.Columns = make([]int16, 2)
		msg.Columns[0] = ColumnFormatBinary
		msg.Columns[1] = ColumnFormatBinary

		t.Run("Write", func(t *testing.T) {
			var buf bytes.Buffer
			err := msg.Encode(&buf)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(*CopyOutResponse)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("CopyBothResponse", func(t *testing.T) {
		var data bytes.Buffer
		writeByte(&data, msgKindCopyBothResponse)
		writeInt32(&data, 11)
		writeInt8(&data, FormatBinary)
		writeInt16(&data, 2)
		writeInt16(&data, ColumnFormatBinary)
		writeInt16(&data, ColumnFormatBinary)

		var msg CopyBothResponse
		msg.Format = FormatBinary
		msg.Columns = make([]int16, 2)
		msg.Columns[0] = ColumnFormatBinary
		msg.Columns[1] = ColumnFormatBinary

		t.Run("Write", func(t *testing.T) {
			var buf bytes.Buffer
			err := msg.Encode(&buf)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(*CopyBothResponse)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("DataRow", func(t *testing.T) {
		var data bytes.Buffer
		writeByte(&data, msgKindDataRow)
		writeInt32(&data, 32)
		writeInt16(&data, 4)
		writeInt32(&data, 5)
		writeBytes(&data, []byte("hello"))
		writeInt32(&data, -1)
		writeInt32(&data, 0)
		writeInt32(&data, 5)
		writeBytes(&data, []byte("world"))

		var msg DataRow
		msg.Columns = [][]byte{
			[]byte("hello"),
			nil,
			[]byte{},
			[]byte("world"),
		}

		t.Run("Write", func(t *testing.T) {
			var buf bytes.Buffer
			err := msg.Encode(&buf)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(*DataRow)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("EmptyQueryResponse", func(t *testing.T) {
		var data bytes.Buffer
		writeByte(&data, msgKindEmptyQueryResponse)
		writeInt32(&data, 4)

		var msg EmptyQueryResponse

		t.Run("Write", func(t *testing.T) {
			var buf bytes.Buffer
			err := msg.Encode(&buf)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(*EmptyQueryResponse)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("ErrorResponse", func(t *testing.T) {
		var data bytes.Buffer
		writeByte(&data, msgKindErrorResponse)
		writeInt32(&data, 25)
		writeByte(&data, FieldSeverity)
		writeString(&data, "ERROR")
		writeByte(&data, FieldMessage)
		writeString(&data, "hello world")
		writeByte(&data, 0)

		var msg ErrorResponse
		msg.Fields = []byte{
			FieldSeverity,
			FieldMessage,
		}
		msg.Values = []string{
			"ERROR",
			"hello world",
		}

		t.Run("Write", func(t *testing.T) {
			var buf bytes.Buffer
			err := msg.Encode(&buf)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(*ErrorResponse)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("FunctionCallResponse", func(t *testing.T) {
		var dataNil bytes.Buffer
		writeByte(&dataNil, msgKindFunctionCallResponse)
		writeInt32(&dataNil, 8)
		writeInt32(&dataNil, -1)

		var msgNil FunctionCallResponse
		msgNil.Result = nil

		var dataZero bytes.Buffer
		writeByte(&dataZero, msgKindFunctionCallResponse)
		writeInt32(&dataZero, 8)
		writeInt32(&dataZero, 0)

		var msgZero FunctionCallResponse
		msgZero.Result = []byte{}

		var dataPresent bytes.Buffer
		writeByte(&dataPresent, msgKindFunctionCallResponse)
		writeInt32(&dataPresent, 19)
		writeInt32(&dataPresent, 11)
		writeBytes(&dataPresent, []byte("hello world"))

		var msgPresent FunctionCallResponse
		msgPresent.Result = []byte("hello world")

		t.Run("Write", func(t *testing.T) {
			t.Run("Nil", func(t *testing.T) {
				var buf bytes.Buffer
				err := msgNil.Encode(&buf)
				require.NoError(t, err)

				require.Equal(t, dataNil.Bytes(), buf.Bytes())
			})

			t.Run("Zero", func(t *testing.T) {
				var buf bytes.Buffer
				err := msgZero.Encode(&buf)
				require.NoError(t, err)

				require.Equal(t, dataZero.Bytes(), buf.Bytes())
			})

			t.Run("Present", func(t *testing.T) {
				var buf bytes.Buffer
				err := msgPresent.Encode(&buf)
				require.NoError(t, err)

				require.Equal(t, dataPresent.Bytes(), buf.Bytes())
			})
		})

		t.Run("Read", func(t *testing.T) {
			t.Run("Nil", func(t *testing.T) {
				value, err := Read(&dataNil)
				require.NoError(t, err)

				m, ok := value.(*FunctionCallResponse)
				require.True(t, ok)

				require.Equal(t, &msgNil, m)
			})

			t.Run("Zero", func(t *testing.T) {
				value, err := Read(&dataZero)
				require.NoError(t, err)

				m, ok := value.(*FunctionCallResponse)
				require.True(t, ok)

				require.Equal(t, &msgZero, m)
			})

			t.Run("Present", func(t *testing.T) {
				value, err := Read(&dataPresent)
				require.NoError(t, err)

				m, ok := value.(*FunctionCallResponse)
				require.True(t, ok)

				require.Equal(t, &msgPresent, m)
			})
		})
	})

	t.Run("NegotiateProtocolVersion", func(t *testing.T) {
		var data bytes.Buffer
		writeByte(&data, msgKindNegotiateProtocolVersion)
		writeInt32(&data, 24)
		writeInt32(&data, 111)      // newest supported minor version
		writeInt32(&data, 2)        // number of unrecognized protocols
		writeString(&data, "hello") // first unrecognized protocol
		writeString(&data, "world") // second unrecognized protocol

		var msg NegotiateProtocolVersion
		msg.MinorVersionSupported = 111
		msg.UnrecognizedOptions = []string{
			"hello",
			"world",
		}

		t.Run("Write", func(t *testing.T) {
			var buf bytes.Buffer
			err := msg.Encode(&buf)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(*NegotiateProtocolVersion)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("NoData", func(t *testing.T) {
		var data bytes.Buffer
		writeByte(&data, msgKindNoData)
		writeInt32(&data, 4)

		var msg NoData

		t.Run("Write", func(t *testing.T) {
			var buf bytes.Buffer
			err := msg.Encode(&buf)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(*NoData)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("NoticeResponse", func(t *testing.T) {
		var data bytes.Buffer
		writeByte(&data, msgKindNoticeResponse)
		writeInt32(&data, 27)
		writeByte(&data, FieldSeverity)
		writeString(&data, "WARNING")
		writeByte(&data, FieldMessage)
		writeString(&data, "hello world")
		writeByte(&data, 0)

		var msg NoticeResponse
		msg.Fields = []byte{
			FieldSeverity,
			FieldMessage,
		}
		msg.Values = []string{
			"WARNING",
			"hello world",
		}

		t.Run("Write", func(t *testing.T) {
			var buf bytes.Buffer
			err := msg.Encode(&buf)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(*NoticeResponse)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("NotificationResponse", func(t *testing.T) {
		var data bytes.Buffer
		writeByte(&data, msgKindNotificationResponse)
		writeInt32(&data, 20)
		writeInt32(&data, 111)
		writeString(&data, "hello")
		writeString(&data, "world")

		var msg NotificationResponse
		msg.ProcessID = 111
		msg.Channel = "hello"
		msg.Payload = "world"

		t.Run("Write", func(t *testing.T) {
			var buf bytes.Buffer
			err := msg.Encode(&buf)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(*NotificationResponse)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("ParameterDescription", func(t *testing.T) {
		var data bytes.Buffer
		writeByte(&data, msgKindParameterDescription)
		writeInt32(&data, 14)
		writeInt16(&data, 2)
		writeInt32(&data, 1)
		writeInt32(&data, 2)

		var msg ParameterDescription
		msg.Parameters = []int32{
			1,
			2,
		}

		t.Run("Write", func(t *testing.T) {
			var buf bytes.Buffer
			err := msg.Encode(&buf)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(*ParameterDescription)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("ParameterStatus", func(t *testing.T) {
		var data bytes.Buffer
		writeByte(&data, msgKindParameterStatus)
		writeInt32(&data, 16)
		writeString(&data, "hello")
		writeString(&data, "world")

		var msg ParameterStatus
		msg.Name = "hello"
		msg.Value = "world"

		t.Run("Write", func(t *testing.T) {
			var buf bytes.Buffer
			err := msg.Encode(&buf)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(*ParameterStatus)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("ParseComplete", func(t *testing.T) {
		var data bytes.Buffer
		writeByte(&data, msgKindParseComplete)
		writeInt32(&data, 4)

		var msg ParseComplete

		t.Run("Write", func(t *testing.T) {
			var buf bytes.Buffer
			err := msg.Encode(&buf)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(*ParseComplete)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("PortalSuspended", func(t *testing.T) {
		var data bytes.Buffer
		writeByte(&data, msgKindPortalSuspended)
		writeInt32(&data, 4)

		var msg PortalSuspended

		t.Run("Write", func(t *testing.T) {
			var buf bytes.Buffer
			err := msg.Encode(&buf)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(*PortalSuspended)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("ReadyForQuery", func(t *testing.T) {
		var data bytes.Buffer
		writeByte(&data, msgKindReadyForQuery)
		writeInt32(&data, 5)
		writeByte(&data, TxStatusActive)

		var msg ReadyForQuery
		msg.TxStatus = TxStatusActive

		t.Run("Write", func(t *testing.T) {
			var buf bytes.Buffer
			err := msg.Encode(&buf)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(*ReadyForQuery)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("RowDescription", func(t *testing.T) {
		var data bytes.Buffer
		writeByte(&data, msgKindRowDescription)
		writeInt32(&data, 54)
		writeInt16(&data, 2)

		writeString(&data, "hello")
		writeInt32(&data, 101)
		writeInt16(&data, 102)
		writeInt32(&data, 103)
		writeInt16(&data, 104)
		writeInt32(&data, 105)
		writeInt16(&data, ColumnFormatBinary)

		writeString(&data, "world")
		writeInt32(&data, 201)
		writeInt16(&data, 202)
		writeInt32(&data, 203)
		writeInt16(&data, 204)
		writeInt32(&data, 205)
		writeInt16(&data, ColumnFormatBinary)

		var msg RowDescription
		msg.Names = []string{
			"hello",
			"world",
		}
		msg.Tables = []int32{
			101,
			201,
		}
		msg.Columns = []int16{
			102,
			202,
		}
		msg.DataTypes = []int32{
			103,
			203,
		}
		msg.Sizes = []int16{
			104,
			204,
		}
		msg.Modifiers = []int32{
			105,
			205,
		}
		msg.Formats = []int16{
			ColumnFormatBinary,
			ColumnFormatBinary,
		}

		t.Run("Write", func(t *testing.T) {
			var buf bytes.Buffer
			err := msg.Encode(&buf)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(*RowDescription)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("UnknownMessage", func(t *testing.T) {
		var data bytes.Buffer
		writeByte(&data, 0x0)
		writeInt32(&data, 4)

		var msg Unknown

		t.Run("Write", func(t *testing.T) {
			var buf bytes.Buffer
			err := msg.Encode(&buf)
			require.ErrorIs(t, err, ErrInvalidValue)
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.ErrorIs(t, err, ErrInvalidValue)
			require.Nil(t, value)
		})
	})

	t.Run("UnknownAuthentication", func(t *testing.T) {
		var data bytes.Buffer
		writeByte(&data, msgKindAuthentication)
		writeInt32(&data, 8)
		writeInt32(&data, -1)

		var msg Unknown

		t.Run("Write", func(t *testing.T) {
			var buf bytes.Buffer
			err := msg.Encode(&buf)
			require.ErrorIs(t, err, ErrInvalidValue)
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.ErrorIs(t, err, ErrInvalidValue)
			require.Nil(t, value)
		})
	})
}

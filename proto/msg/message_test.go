package proto

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
	t.Run("MsgAuthOk", func(t *testing.T) {
		var data bytes.Buffer
		_ = writeByte(&data, msgKindAuthentication)
		_ = writeInt32(&data, 8)
		_ = writeInt32(&data, authKindOk)

		var msg MsgAuthOk

		t.Run("Write", func(t *testing.T) {
			var buf bytes.Buffer
			err := msg.Encode(&buf)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(*MsgAuthOk)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("MsgAuthKerberosV5", func(t *testing.T) {
		var data bytes.Buffer
		_ = writeByte(&data, msgKindAuthentication)
		_ = writeInt32(&data, 8)
		_ = writeInt32(&data, authKindKerberosV5)

		var msg MsgAuthKerberosV5

		t.Run("Write", func(t *testing.T) {
			var buf bytes.Buffer
			err := msg.Encode(&buf)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(*MsgAuthKerberosV5)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("MsgAuthCleartextPassword", func(t *testing.T) {
		var data bytes.Buffer
		_ = writeByte(&data, msgKindAuthentication)
		_ = writeInt32(&data, 8)
		_ = writeInt32(&data, authKindCleartextPassword)

		var msg MsgAuthCleartextPassword

		t.Run("Write", func(t *testing.T) {
			var buf bytes.Buffer
			err := msg.Encode(&buf)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(*MsgAuthCleartextPassword)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("MsgAuthMD5Password", func(t *testing.T) {
		var data bytes.Buffer
		_ = writeByte(&data, msgKindAuthentication)
		_ = writeInt32(&data, 12)
		_ = writeInt32(&data, authKindMD5Password)
		_ = writeBytes(&data, []byte("abcd"))

		var msg MsgAuthMD5Password
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

			m, ok := value.(*MsgAuthMD5Password)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("MsgAuthGSS", func(t *testing.T) {
		var data bytes.Buffer
		_ = writeByte(&data, msgKindAuthentication)
		_ = writeInt32(&data, 8)
		_ = writeInt32(&data, authKindGSS)

		var msg MsgAuthGSS

		t.Run("Write", func(t *testing.T) {
			var buf bytes.Buffer
			err := msg.Encode(&buf)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(*MsgAuthGSS)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("MsgAuthGSSContinue", func(t *testing.T) {
		var data bytes.Buffer
		_ = writeByte(&data, msgKindAuthentication)
		_ = writeInt32(&data, 13)
		_ = writeInt32(&data, authKindGSSContinue)
		_ = writeBytes(&data, []byte("hello"))

		var msg MsgAuthGSSContinue
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

			m, ok := value.(*MsgAuthGSSContinue)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("MsgAuthSSPI", func(t *testing.T) {
		var data bytes.Buffer
		_ = writeByte(&data, msgKindAuthentication)
		_ = writeInt32(&data, 8)
		_ = writeInt32(&data, authKindSSPI)

		var msg MsgAuthSSPI

		t.Run("Write", func(t *testing.T) {
			var buf bytes.Buffer
			err := msg.Encode(&buf)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(*MsgAuthSSPI)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("MsgAuthSASL", func(t *testing.T) {
		var data bytes.Buffer
		_ = writeByte(&data, msgKindAuthentication)
		_ = writeInt32(&data, 23)
		_ = writeInt32(&data, authKindSASL)
		_ = writeString(&data, "one")
		_ = writeString(&data, "two")
		_ = writeString(&data, "three")
		_ = writeByte(&data, 0x0)

		var msg MsgAuthSASL
		msg.Mechanisms = []string{"one", "two", "three"}

		var dataZero bytes.Buffer
		_ = writeByte(&dataZero, msgKindAuthentication)
		_ = writeInt32(&dataZero, 9)
		_ = writeInt32(&dataZero, authKindSASL)
		_ = writeByte(&dataZero, 0x0)

		var msgZero MsgAuthSASL
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

				m, ok := value.(*MsgAuthSASL)
				require.True(t, ok)

				require.Equal(t, &msg, m)
			})

			t.Run("Zero", func(t *testing.T) {
				value, err := Read(&dataZero)
				require.NoError(t, err)

				m, ok := value.(*MsgAuthSASL)
				require.True(t, ok)

				require.Equal(t, &msgZero, m)
			})
		})
	})

	t.Run("MsgAuthSASLContinue", func(t *testing.T) {
		var data bytes.Buffer
		_ = writeByte(&data, msgKindAuthentication)
		_ = writeInt32(&data, 13)
		_ = writeInt32(&data, authKindSASLContinue)
		_ = writeBytes(&data, []byte("hello"))

		var msg MsgAuthSASLContinue
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

			m, ok := value.(*MsgAuthSASLContinue)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("MsgAuthSASLFinal", func(t *testing.T) {
		var data bytes.Buffer
		_ = writeByte(&data, msgKindAuthentication)
		_ = writeInt32(&data, 13)
		_ = writeInt32(&data, authKindSASLFinal)
		_ = writeBytes(&data, []byte("hello"))

		var msg MsgAuthSASLFinal
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

			m, ok := value.(*MsgAuthSASLFinal)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("MsgBackendKeyData", func(t *testing.T) {
		var data bytes.Buffer
		_ = writeByte(&data, msgKindBackendKeyData)
		_ = writeInt32(&data, 13)
		_ = writeInt32(&data, 111)
		_ = writeBytes(&data, []byte("hello"))

		var msg MsgBackendKeyData
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

			m, ok := value.(*MsgBackendKeyData)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("MsgBind", func(t *testing.T) {
		var data bytes.Buffer
		_ = writeByte(&data, msgKindBind)
		_ = writeInt32(&data, 44)
		_ = writeString(&data, "hello")
		_ = writeString(&data, "world")
		_ = writeInt16(&data, 1)
		_ = writeInt16(&data, ColumnFormatBinary)
		_ = writeInt16(&data, 2)
		_ = writeInt32(&data, 5)
		_ = writeBytes(&data, []byte("hello"))
		_ = writeInt32(&data, 5)
		_ = writeBytes(&data, []byte("world"))
		_ = writeInt16(&data, 1)
		_ = writeInt16(&data, ColumnFormatBinary)

		var msg MsgBind
		msg.DestinationName = "hello"
		msg.SourceName = "world"
		msg.ParameterFormatCodes = []int16{
			ColumnFormatBinary,
		}
		msg.ParameterData = [][]byte{
			[]byte("hello"),
			[]byte("world"),
		}
		msg.ColumnFormatCodes = []int16{
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

			m, ok := value.(*MsgBind)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("MsgBindComplete", func(t *testing.T) {
		var data bytes.Buffer
		_ = writeByte(&data, msgKindBindComplete)
		_ = writeInt32(&data, 4)

		var msg MsgBindComplete

		t.Run("Write", func(t *testing.T) {
			var buf bytes.Buffer
			err := msg.Encode(&buf)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(*MsgBindComplete)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("MsgCancelRequest", func(t *testing.T) {
		var data bytes.Buffer
		_ = writeInt32(&data, 17)
		_ = writeInt32(&data, codeCancelRequest)
		_ = writeInt32(&data, 1234)
		_ = writeBytes(&data, []byte("hello"))

		var msg MsgCancelRequest
		msg.ProcessID = 1234
		msg.SecretKey = []byte("hello")

		t.Run("Write", func(t *testing.T) {
			var buf bytes.Buffer
			err := msg.Encode(&buf)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := ReadFirst(&data)
			require.NoError(t, err)

			m, ok := value.(*MsgCancelRequest)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("MsgCloseComplete", func(t *testing.T) {
		var data bytes.Buffer
		_ = writeByte(&data, msgKindCloseComplete)
		_ = writeInt32(&data, 4)

		var msg MsgCloseComplete

		t.Run("Write", func(t *testing.T) {
			var buf bytes.Buffer
			err := msg.Encode(&buf)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(*MsgCloseComplete)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("MsgCommandComplete", func(t *testing.T) {
		var data bytes.Buffer
		_ = writeByte(&data, msgKindCommandComplete)
		_ = writeInt32(&data, 17)
		_ = writeString(&data, "INSERT 11 11")

		var msg MsgCommandComplete
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

			m, ok := value.(*MsgCommandComplete)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("MsgCopyData", func(t *testing.T) {
		var data bytes.Buffer
		_ = writeByte(&data, msgKindCopyData)
		_ = writeInt32(&data, 9)
		_ = writeBytes(&data, []byte("hello"))

		var msg MsgCopyData
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

			m, ok := value.(*MsgCopyData)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("MsgCopyDone", func(t *testing.T) {
		var data bytes.Buffer
		_ = writeByte(&data, msgKindCopyDone)
		_ = writeInt32(&data, 4)

		var msg MsgCopyDone

		t.Run("Write", func(t *testing.T) {
			var buf bytes.Buffer
			err := msg.Encode(&buf)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(*MsgCopyDone)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("MsgCopyInResponse", func(t *testing.T) {
		var data bytes.Buffer
		_ = writeByte(&data, msgKindCopyInResponse)
		_ = writeInt32(&data, 11)
		_ = writeInt8(&data, FormatBinary)
		_ = writeInt16(&data, 2)
		_ = writeInt16(&data, ColumnFormatBinary)
		_ = writeInt16(&data, ColumnFormatBinary)

		var msg MsgCopyInResponse
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

			m, ok := value.(*MsgCopyInResponse)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("MsgCopyOutResponse", func(t *testing.T) {
		var data bytes.Buffer
		_ = writeByte(&data, msgKindCopyOutResponse)
		_ = writeInt32(&data, 11)
		_ = writeInt8(&data, FormatBinary)
		_ = writeInt16(&data, 2)
		_ = writeInt16(&data, ColumnFormatBinary)
		_ = writeInt16(&data, ColumnFormatBinary)

		var msg MsgCopyOutResponse
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

			m, ok := value.(*MsgCopyOutResponse)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("MsgCopyBothResponse", func(t *testing.T) {
		var data bytes.Buffer
		_ = writeByte(&data, msgKindCopyBothResponse)
		_ = writeInt32(&data, 11)
		_ = writeInt8(&data, FormatBinary)
		_ = writeInt16(&data, 2)
		_ = writeInt16(&data, ColumnFormatBinary)
		_ = writeInt16(&data, ColumnFormatBinary)

		var msg MsgCopyBothResponse
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

			m, ok := value.(*MsgCopyBothResponse)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("MsgDataRow", func(t *testing.T) {
		var data bytes.Buffer
		_ = writeByte(&data, msgKindDataRow)
		_ = writeInt32(&data, 32)
		_ = writeInt16(&data, 4)
		_ = writeInt32(&data, 5)
		_ = writeBytes(&data, []byte("hello"))
		_ = writeInt32(&data, -1)
		_ = writeInt32(&data, 0)
		_ = writeInt32(&data, 5)
		_ = writeBytes(&data, []byte("world"))

		var msg MsgDataRow
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

			m, ok := value.(*MsgDataRow)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("MsgEmptyQueryResponse", func(t *testing.T) {
		var data bytes.Buffer
		_ = writeByte(&data, msgKindEmptyQueryResponse)
		_ = writeInt32(&data, 4)

		var msg MsgEmptyQueryResponse

		t.Run("Write", func(t *testing.T) {
			var buf bytes.Buffer
			err := msg.Encode(&buf)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(*MsgEmptyQueryResponse)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("MsgErrorResponse", func(t *testing.T) {
		var data bytes.Buffer
		_ = writeByte(&data, msgKindErrorResponse)
		_ = writeInt32(&data, 25)
		_ = writeByte(&data, FieldSeverity)
		_ = writeString(&data, "ERROR")
		_ = writeByte(&data, FieldMessage)
		_ = writeString(&data, "hello world")
		_ = writeByte(&data, 0)

		var msg MsgErrorResponse
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

			m, ok := value.(*MsgErrorResponse)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("MsgFunctionCallResponse", func(t *testing.T) {
		var dataNil bytes.Buffer
		_ = writeByte(&dataNil, msgKindFunctionCallResponse)
		_ = writeInt32(&dataNil, 8)
		_ = writeInt32(&dataNil, -1)

		var msgNil MsgFunctionCallResponse
		msgNil.Result = nil

		var dataZero bytes.Buffer
		_ = writeByte(&dataZero, msgKindFunctionCallResponse)
		_ = writeInt32(&dataZero, 8)
		_ = writeInt32(&dataZero, 0)

		var msgZero MsgFunctionCallResponse
		msgZero.Result = []byte{}

		var dataPresent bytes.Buffer
		_ = writeByte(&dataPresent, msgKindFunctionCallResponse)
		_ = writeInt32(&dataPresent, 19)
		_ = writeInt32(&dataPresent, 11)
		_ = writeBytes(&dataPresent, []byte("hello world"))

		var msgPresent MsgFunctionCallResponse
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

				m, ok := value.(*MsgFunctionCallResponse)
				require.True(t, ok)

				require.Equal(t, &msgNil, m)
			})

			t.Run("Zero", func(t *testing.T) {
				value, err := Read(&dataZero)
				require.NoError(t, err)

				m, ok := value.(*MsgFunctionCallResponse)
				require.True(t, ok)

				require.Equal(t, &msgZero, m)
			})

			t.Run("Present", func(t *testing.T) {
				value, err := Read(&dataPresent)
				require.NoError(t, err)

				m, ok := value.(*MsgFunctionCallResponse)
				require.True(t, ok)

				require.Equal(t, &msgPresent, m)
			})
		})
	})

	t.Run("MsgNegotiateProtocolVersion", func(t *testing.T) {
		var data bytes.Buffer
		_ = writeByte(&data, msgKindNegotiateProtocolVersion)
		_ = writeInt32(&data, 24)
		_ = writeInt32(&data, 111)      // newest supported minor version
		_ = writeInt32(&data, 2)        // number of unrecognized protocols
		_ = writeString(&data, "hello") // first unrecognized protocol
		_ = writeString(&data, "world") // second unrecognized protocol

		var msg MsgNegotiateProtocolVersion
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

			m, ok := value.(*MsgNegotiateProtocolVersion)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("MsgNoData", func(t *testing.T) {
		var data bytes.Buffer
		_ = writeByte(&data, msgKindNoData)
		_ = writeInt32(&data, 4)

		var msg MsgNoData

		t.Run("Write", func(t *testing.T) {
			var buf bytes.Buffer
			err := msg.Encode(&buf)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(*MsgNoData)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("MsgNoticeResponse", func(t *testing.T) {
		var data bytes.Buffer
		_ = writeByte(&data, msgKindNoticeResponse)
		_ = writeInt32(&data, 27)
		_ = writeByte(&data, FieldSeverity)
		_ = writeString(&data, "WARNING")
		_ = writeByte(&data, FieldMessage)
		_ = writeString(&data, "hello world")
		_ = writeByte(&data, 0)

		var msg MsgNoticeResponse
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

			m, ok := value.(*MsgNoticeResponse)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("MsgNotificationResponse", func(t *testing.T) {
		var data bytes.Buffer
		_ = writeByte(&data, msgKindNotificationResponse)
		_ = writeInt32(&data, 20)
		_ = writeInt32(&data, 111)
		_ = writeString(&data, "hello")
		_ = writeString(&data, "world")

		var msg MsgNotificationResponse
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

			m, ok := value.(*MsgNotificationResponse)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("MsgParameterDescription", func(t *testing.T) {
		var data bytes.Buffer
		_ = writeByte(&data, msgKindParameterDescription)
		_ = writeInt32(&data, 14)
		_ = writeInt16(&data, 2)
		_ = writeInt32(&data, 1)
		_ = writeInt32(&data, 2)

		var msg MsgParameterDescription
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

			m, ok := value.(*MsgParameterDescription)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("MsgParameterStatus", func(t *testing.T) {
		var data bytes.Buffer
		_ = writeByte(&data, msgKindParameterStatus)
		_ = writeInt32(&data, 16)
		_ = writeString(&data, "hello")
		_ = writeString(&data, "world")

		var msg MsgParameterStatus
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

			m, ok := value.(*MsgParameterStatus)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("MsgParseComplete", func(t *testing.T) {
		var data bytes.Buffer
		_ = writeByte(&data, msgKindParseComplete)
		_ = writeInt32(&data, 4)

		var msg MsgParseComplete

		t.Run("Write", func(t *testing.T) {
			var buf bytes.Buffer
			err := msg.Encode(&buf)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(*MsgParseComplete)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("MsgPortalSuspended", func(t *testing.T) {
		var data bytes.Buffer
		_ = writeByte(&data, msgKindPortalSuspended)
		_ = writeInt32(&data, 4)

		var msg MsgPortalSuspended

		t.Run("Write", func(t *testing.T) {
			var buf bytes.Buffer
			err := msg.Encode(&buf)
			require.NoError(t, err)

			require.Equal(t, data.Bytes(), buf.Bytes())
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.NoError(t, err)

			m, ok := value.(*MsgPortalSuspended)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("MsgReadyForQuery", func(t *testing.T) {
		var data bytes.Buffer
		_ = writeByte(&data, msgKindReadyForQuery)
		_ = writeInt32(&data, 5)
		_ = writeByte(&data, TxStatusActive)

		var msg MsgReadyForQuery
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

			m, ok := value.(*MsgReadyForQuery)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("MsgRowDescription", func(t *testing.T) {
		var data bytes.Buffer
		_ = writeByte(&data, msgKindRowDescription)
		_ = writeInt32(&data, 54)
		_ = writeInt16(&data, 2)

		_ = writeString(&data, "hello")
		_ = writeInt32(&data, 101)
		_ = writeInt16(&data, 102)
		_ = writeInt32(&data, 103)
		_ = writeInt16(&data, 104)
		_ = writeInt32(&data, 105)
		_ = writeInt16(&data, ColumnFormatBinary)

		_ = writeString(&data, "world")
		_ = writeInt32(&data, 201)
		_ = writeInt16(&data, 202)
		_ = writeInt32(&data, 203)
		_ = writeInt16(&data, 204)
		_ = writeInt32(&data, 205)
		_ = writeInt16(&data, ColumnFormatBinary)

		var msg MsgRowDescription
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

			m, ok := value.(*MsgRowDescription)
			require.True(t, ok)

			require.Equal(t, &msg, m)
		})
	})

	t.Run("MsgUnknown", func(t *testing.T) {
		var data bytes.Buffer
		_ = writeByte(&data, 0x0)
		_ = writeInt32(&data, 4)

		var msg MsgUnknown

		t.Run("Write", func(t *testing.T) {
			var buf bytes.Buffer
			err := msg.Encode(&buf)
			require.ErrorIs(t, err, ErrUnknownMessageType)
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.ErrorIs(t, err, ErrUnknownMessageType)
			require.Nil(t, value)
		})
	})

	t.Run("MsgUnknownAuth", func(t *testing.T) {
		var data bytes.Buffer
		_ = writeByte(&data, msgKindAuthentication)
		_ = writeInt32(&data, 8)
		_ = writeInt32(&data, -1)

		var msg MsgUnknownAuth

		t.Run("Write", func(t *testing.T) {
			var buf bytes.Buffer
			err := msg.Encode(&buf)
			require.ErrorIs(t, err, ErrUnknownAuthType)
		})

		t.Run("Read", func(t *testing.T) {
			value, err := Read(&data)
			require.ErrorIs(t, err, ErrUnknownAuthType)
			require.Nil(t, value)
		})
	})
}

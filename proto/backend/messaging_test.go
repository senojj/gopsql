package backend

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

func writeKind(buf *bytes.Buffer, k Kind) {
	buf.WriteByte(byte(k))
}

func writeInt32(buf *bytes.Buffer, i uint32) {
	bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(bytes, i)

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

func as[T any](buf *bytes.Buffer, v *T) (bool, error) {
	var m Message

	err := m.Unmarshal(buf)
	if err != nil {
		return false, err
	}

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

		first, b := readInt8(b)
		require.Equal(t, int8(0), first)
		require.Equal(t, []byte(nil), b)
	})

	t.Run("one", func(t *testing.T) {
		b := []byte{byte(1)}

		first, b := readInt8(b)
		require.Equal(t, int8(1), first)
		require.Equal(t, []byte{}, b)
	})

	t.Run("two", func(t *testing.T) {
		b := []byte{byte(1), byte(2)}

		first, b := readInt8(b)
		require.Equal(t, int8(1), first)
		require.Equal(t, []byte{byte(2)}, b)

		second, b := readInt8(b)
		require.Equal(t, int8(2), second)
		require.Equal(t, []byte{}, b)
	})
}

func TestReadString(t *testing.T) {
	t.Run("iterative", func(t *testing.T) {
		b := []byte{'a', 'b', 'c', '\x00', 'd', 'e', 'f', '\x00', 'g', 'h', 'i'}

		first, b := readString(b)
		require.Equal(t, "abc", first)
		require.Equal(t, []byte{'d', 'e', 'f', '\x00', 'g', 'h', 'i'}, b)

		second, b := readString(b)
		require.Equal(t, "def", second)
		require.Equal(t, []byte{'g', 'h', 'i'}, b)

		third, b := readString(b)
		require.Equal(t, "ghi", third)
		require.Equal(t, []byte(nil), b)

		fourth, b := readString(b)
		require.Equal(t, "", fourth)
		require.Equal(t, []byte(nil), b)
	})

	t.Run("last_character_null", func(t *testing.T) {
		b := []byte{'a', 'b', 'c', '\x00'}

		first, b := readString(b)
		require.Equal(t, "abc", first)
		require.Equal(t, []byte{}, b)
	})

	t.Run("only_character_null", func(t *testing.T) {
		b := []byte{'\x00'}

		first, b := readString(b)
		require.Equal(t, "", first)
		require.Equal(t, []byte{}, b)
	})
}

func TestParseMessage(t *testing.T) {
	t.Run("AuthenticationOk", func(t *testing.T) {
		var buf bytes.Buffer

		writeKind(&buf, KindAuthentication)
		writeInt32(&buf, 8)
		writeInt32(&buf, 0)

		var result AuthenticationOk

		ok, err := as(&buf, &result)
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("AuthenticationKerberosV5", func(t *testing.T) {
		var buf bytes.Buffer

		writeKind(&buf, KindAuthentication)
		writeInt32(&buf, 8)
		writeInt32(&buf, 2)

		var result AuthenticationKerberosV5

		ok, err := as(&buf, &result)
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("AuthenticationCleartextPassword", func(t *testing.T) {
		var buf bytes.Buffer

		writeKind(&buf, KindAuthentication)
		writeInt32(&buf, 8)
		writeInt32(&buf, 3)

		var result AuthenticationCleartextPassword

		ok, err := as(&buf, &result)
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("AuthenticationMD5Password", func(t *testing.T) {
		var buf bytes.Buffer

		writeKind(&buf, KindAuthentication)
		writeInt32(&buf, 12)             // messsage length
		writeInt32(&buf, 5)              // authentication indicator
		writeBytes(&buf, []byte("abcd")) // salt

		var result AuthenticationMD5Password

		ok, err := as(&buf, &result)
		require.NoError(t, err)
		require.True(t, ok)

		require.Equal(t, [4]byte{'a', 'b', 'c', 'd'}, result.Salt)
	})

	t.Run("AuthenticationGSS", func(t *testing.T) {
		var buf bytes.Buffer

		writeKind(&buf, KindAuthentication)
		writeInt32(&buf, 8)
		writeInt32(&buf, 7)

		var result AuthenticationGSS

		ok, err := as(&buf, &result)
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("AuthenticationGSSContinue", func(t *testing.T) {
		var buf bytes.Buffer

		writeKind(&buf, KindAuthentication)
		writeInt32(&buf, 13)
		writeInt32(&buf, 8)
		writeBytes(&buf, []byte("hello"))

		var result AuthenticationGSSContinue

		ok, err := as(&buf, &result)
		require.NoError(t, err)
		require.True(t, ok)

		require.Equal(t, []byte("hello"), result.Data)
	})
}

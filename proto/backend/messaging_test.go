package backend

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

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

		_ = buf.WriteByte(byte(KindAuthentication))

		byteLength := make([]byte, 4)
		binary.BigEndian.PutUint32(byteLength, 8)

		_, _ = buf.Write(byteLength)

		byteStatus := make([]byte, 4)
		binary.BigEndian.PutUint32(byteStatus, 0)

		_, _ = buf.Write(byteStatus)

		var m Message

		err := m.Unmarshal(&buf)
		require.NoError(t, err)

		require.Equal(t, KindAuthentication, m.kind)
		require.Len(t, m.body, 4)

		v, err := m.Parse()
		require.NoError(t, err)

		_, ok := v.(AuthenticationOk)
		require.True(t, ok)
	})

	t.Run("AuthenticationMD5Password", func(t *testing.T) {
		var buf bytes.Buffer

		_ = buf.WriteByte(byte(KindAuthentication))

		byteLength := make([]byte, 4)
		binary.BigEndian.PutUint32(byteLength, 12)

		_, _ = buf.Write(byteLength)

		byteStatus := make([]byte, 4)
		binary.BigEndian.PutUint32(byteStatus, 5)

		_, _ = buf.Write(byteStatus)

		_, _ = buf.WriteString("abcd")

		var m Message

		err := m.Unmarshal(&buf)
		require.NoError(t, err)

		require.Equal(t, KindAuthentication, m.kind)
		require.Len(t, m.body, 8)

		v, err := m.Parse()
		require.NoError(t, err)

		a, ok := v.(AuthenticationMD5Password)
		require.True(t, ok)
		require.Equal(t, [4]byte{'a', 'b', 'c', 'd'}, a.Salt)
	})
}

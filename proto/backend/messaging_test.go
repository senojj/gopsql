package backend

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

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

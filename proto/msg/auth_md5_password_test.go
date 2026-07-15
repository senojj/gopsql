package msg_test

import (
	"gopsql/internal/bytex"
	"gopsql/proto/msg"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAuthMD5Password(t *testing.T) {
	t.Parallel()

	buf := bytex.NewBuffer(nil)
	buf.AppendByte(msg.KindAuthentication)
	buf.AppendInt32(12)
	buf.AppendInt32(msg.KindAuthMD5Password)
	buf.AppendByte([]byte("4321")...)

	var m msg.AuthMD5Password

	t.Run("UnmarshalBinary", func(t *testing.T) {
		err := m.UnmarshalBinary(buf.Bytes())
		require.NoError(t, err)
		require.Equal(t, "4321", string(m.Salt[:]))
	})

	t.Run("AppendBinary", func(t *testing.T) {
		b, err := m.AppendBinary(nil)
		require.NoError(t, err)
		require.Equal(t, buf.Bytes(), b)
	})
}

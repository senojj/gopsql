package msg_test

import (
	"gopsql/internal/bytex"
	"gopsql/proto/msg"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAuthGSSContinue(t *testing.T) {
	t.Parallel()

	buf := bytex.NewBuffer(nil)
	buf.AppendByte(msg.KindAuthentication)
	buf.AppendInt32(19)
	buf.AppendInt32(msg.KindAuthGSSContinue)
	buf.AppendByte([]byte("hello world")...)

	var m msg.AuthGSSContinue

	t.Run("UnmarshalBinary", func(t *testing.T) {
		err := m.UnmarshalBinary(buf.Bytes())
		require.NoError(t, err)

		require.Equal(t, "hello world", string(m.Data))
	})

	t.Run("AppendBinary", func(t *testing.T) {
		b, err := m.AppendBinary(nil)
		require.NoError(t, err)
		require.Equal(t, buf.Bytes(), b)
	})
}

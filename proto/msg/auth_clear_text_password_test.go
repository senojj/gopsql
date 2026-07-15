package msg_test

import (
	"gopsql/internal/bytex"
	"gopsql/proto/msg"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAuthClearTextPassword(t *testing.T) {
	t.Parallel()

	buf := bytex.NewBuffer(nil)
	buf.AppendByte(msg.KindAuthentication)
	buf.AppendInt32(8)
	buf.AppendInt32(msg.KindAuthCleartextPassword)

	var m msg.AuthCleartextPassword

	t.Run("UnmarshalBinary", func(t *testing.T) {
		err := m.UnmarshalBinary(buf.Bytes())
		require.NoError(t, err)
	})

	t.Run("AppendBinary", func(t *testing.T) {
		result, err := m.AppendBinary(nil)
		require.NoError(t, err)
		require.Equal(t, buf.Bytes(), result)
	})
}

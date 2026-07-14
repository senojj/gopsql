package msg_test

import (
	"gopsql/internal/bytex"
	"gopsql/proto/msg"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAuthKerberosV5(t *testing.T) {
	buf := bytex.NewBuffer(nil)
	buf.AppendByte(msg.KindAuthentication)
	buf.AppendInt32(8)
	buf.AppendInt32(msg.KindAuthKerberosV5)

	var m msg.AuthKerberosV5

	t.Run("UnmarshalBinary", func(t *testing.T) {
		unmarshal(t, buf.Bytes(), &m)
	})

	t.Run("AppendBinary", func(t *testing.T) {
		result, err := m.AppendBinary(nil)
		require.NoError(t, err)
		require.Equal(t, buf.Bytes(), result)
	})
}

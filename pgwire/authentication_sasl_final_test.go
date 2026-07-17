package pgwire_test

import (
	"gopsql/pgio"
	"gopsql/pgwire"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAuthSASLFinal(t *testing.T) {
	t.Parallel()

	buf := pgio.NewBuffer(nil)
	buf.AppendByte(byte(pgwire.MsgAuthentication))
	buf.AppendInt32(19)
	buf.AppendInt32(int32(pgwire.AuthSASLFinal))
	buf.AppendByte([]byte("hello world")...)

	var m pgwire.AuthenticationSASLFinal

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

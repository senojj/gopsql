package pgwire_test

import (
	"gopsql/pgio"
	"gopsql/pgwire"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAuthSASL(t *testing.T) {
	t.Parallel()

	buf := pgio.NewBuffer(nil)
	buf.AppendByte(pgwire.KindAuthentication)
	buf.AppendInt32(21)
	buf.AppendInt32(pgwire.KindAuthSASL)
	buf.AppendString("hello", "world")
	buf.AppendByte(0)

	var m pgwire.AuthenticationSASL

	t.Run("UnmarshalBinary", func(t *testing.T) {
		err := m.UnmarshalBinary(buf.Bytes())
		require.NoError(t, err)
		require.Equal(t, []string{"hello", "world"}, m.Mechanisms)
	})

	t.Run("AppendBinary", func(t *testing.T) {
		b, err := m.AppendBinary(nil)
		require.NoError(t, err)
		require.Equal(t, buf.Bytes(), b)
	})
}

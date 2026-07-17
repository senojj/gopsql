package pgwire_test

import (
	"gopsql/pgio"
	"gopsql/pgwire"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAuthGSSContinue(t *testing.T) {
	t.Parallel()

	buf := pgio.NewBuffer(nil)
	buf.AppendByte(pgwire.KindAuthentication)
	buf.AppendInt32(19)
	buf.AppendInt32(pgwire.KindAuthGSSContinue)
	buf.AppendByte([]byte("hello world")...)

	var m pgwire.AuthenticationGSSContinue

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

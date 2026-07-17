package pgwire_test

import (
	"gopsql/pgio"
	"gopsql/pgwire"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAuthSSPI(t *testing.T) {
	t.Parallel()

	buf := pgio.NewBuffer(nil)
	buf.AppendByte(pgwire.KindAuthentication)
	buf.AppendInt32(8)
	buf.AppendInt32(pgwire.KindAuthSSPI)

	var m pgwire.AuthenticationSSPI

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

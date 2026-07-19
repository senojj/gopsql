package pgwire_test

import (
	"gopsql/pgwire"
	"testing"

	"github.com/stretchr/testify/require"
)

func testMessage(t *testing.T, b []byte, m pgwire.Message, fn func(*testing.T)) {
	t.Run("UnmarshalBinary", func(t *testing.T) {
		err := m.UnmarshalBinary(b)
		require.NoError(t, err)

		if fn != nil {
			fn(t)
		}
	})

	t.Run("AppendBinary", func(t *testing.T) {
		got, err := m.AppendBinary(nil)
		require.NoError(t, err)
		require.Equal(t, b, got)
	})
}

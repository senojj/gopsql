package pgwire_test

import (
	"gopsql/pgwire"
	"testing"

	"github.com/stretchr/testify/require"
)

func unmarshalTest[T pgwire.Message](t *testing.T, b []byte, m T, fn func(*testing.T, T)) {
	t.Run("UnmarshalBinary", func(t *testing.T) {
		err := m.UnmarshalBinary(b)
		require.NoError(t, err)
		fn(t, m)
	})
}

func appendTest[T pgwire.Message](t *testing.T, m T, want []byte) {
	t.Run("AppendBinary", func(t *testing.T) {
		got, err := m.AppendBinary(nil)
		require.NoError(t, err)
		require.Equal(t, want, got)
	})
}

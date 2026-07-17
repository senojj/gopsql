package pgwire_test

import (
	"gopsql/pgio"
	"gopsql/pgwire"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBind(t *testing.T) {
	t.Parallel()

	buf := pgio.NewBuffer(nil)
	buf.AppendByte(byte(pgwire.MsgBind))
	buf.AppendInt32(73)
	buf.AppendString("hello world")
	buf.AppendString("lorem ipsum")
	buf.AppendInt16(3)
	buf.AppendInt16(int16(pgwire.FmtBinary), int16(pgwire.FmtBinary), int16(pgwire.FmtBinary))
	buf.AppendInt16(3)
	buf.AppendInt32(5)
	buf.AppendByte([]byte("lorem")...)
	buf.AppendInt32(5)
	buf.AppendByte([]byte("ipsum")...)
	buf.AppendInt32(5)
	buf.AppendByte([]byte("dolor")...)
	buf.AppendInt16(3)
	buf.AppendInt16(int16(pgwire.FmtBinary), int16(pgwire.FmtBinary), int16(pgwire.FmtBinary))

	var m pgwire.Bind

	t.Run("UnmarshalBinary", func(t *testing.T) {
		err := m.UnmarshalBinary(buf.Bytes())
		require.NoError(t, err)
		require.Equal(t, "hello world", m.DestinationName)
		require.Equal(t, "lorem ipsum", m.SourceName)
		require.Equal(t, []int16{int16(pgwire.FmtBinary), int16(pgwire.FmtBinary), int16(pgwire.FmtBinary)}, m.ParameterFormatCodes)
		require.Equal(t, [][]byte{[]byte("lorem"), []byte("ipsum"), []byte("dolor")}, m.ParameterData)
		require.Equal(t, []int16{int16(pgwire.FmtBinary), int16(pgwire.FmtBinary), int16(pgwire.FmtBinary)}, m.ColumnFormatCodes)
	})

	t.Run("AppendBinary", func(t *testing.T) {
		b, err := m.AppendBinary(nil)
		require.NoError(t, err)
		require.Equal(t, buf.Bytes(), b)
	})
}

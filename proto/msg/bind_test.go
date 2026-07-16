package msg_test

import (
	"gopsql/internal/bytex"
	"gopsql/proto/msg"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBind(t *testing.T) {
	t.Parallel()

	buf := bytex.NewBuffer(nil)
	buf.AppendByte(msg.KindBind)
	buf.AppendInt32(73)
	buf.AppendString("hello world")
	buf.AppendString("lorem ipsum")
	buf.AppendInt16(3)
	buf.AppendInt16(msg.FormatBinary16, msg.FormatBinary16, msg.FormatBinary16)
	buf.AppendInt16(3)
	buf.AppendInt32(5)
	buf.AppendByte([]byte("lorem")...)
	buf.AppendInt32(5)
	buf.AppendByte([]byte("ipsum")...)
	buf.AppendInt32(5)
	buf.AppendByte([]byte("dolor")...)
	buf.AppendInt16(3)
	buf.AppendInt16(msg.FormatBinary16, msg.FormatBinary16, msg.FormatBinary16)

	var m msg.Bind

	t.Run("UnmarshalBinary", func(t *testing.T) {
		err := m.UnmarshalBinary(buf.Bytes())
		require.NoError(t, err)
		require.Equal(t, "hello world", m.DestinationName)
		require.Equal(t, "lorem ipsum", m.SourceName)
		require.Equal(t, []int16{msg.FormatBinary16, msg.FormatBinary16, msg.FormatBinary16}, m.ParameterFormatCodes)
		require.Equal(t, [][]byte{[]byte("lorem"), []byte("ipsum"), []byte("dolor")}, m.ParameterData)
		require.Equal(t, []int16{msg.FormatBinary16, msg.FormatBinary16, msg.FormatBinary16}, m.ColumnFormatCodes)
	})

	t.Run("AppendBinary", func(t *testing.T) {
		b, err := m.AppendBinary(nil)
		require.NoError(t, err)
		require.Equal(t, buf.Bytes(), b)
	})
}

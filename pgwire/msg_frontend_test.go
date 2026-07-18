package pgwire_test

import (
	"gopsql/pgio"
	"gopsql/pgwire"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMsgBind(t *testing.T) {
	t.Parallel()

	buf := pgio.NewBuffer(nil)
	buf.AppendByte(byte(pgwire.MessageKindBind))
	buf.AppendInt32(73)
	buf.AppendString("hello world")
	buf.AppendString("lorem ipsum")
	buf.AppendInt16(3)
	buf.AppendInt16(int16(pgwire.FormatKindBinary), int16(pgwire.FormatKindBinary), int16(pgwire.FormatKindBinary))
	buf.AppendInt16(3)
	buf.AppendInt32(5)
	buf.AppendByte([]byte("lorem")...)
	buf.AppendInt32(5)
	buf.AppendByte([]byte("ipsum")...)
	buf.AppendInt32(5)
	buf.AppendByte([]byte("dolor")...)
	buf.AppendInt16(3)
	buf.AppendInt16(int16(pgwire.FormatKindBinary), int16(pgwire.FormatKindBinary), int16(pgwire.FormatKindBinary))

	var m pgwire.MsgBind

	t.Run("UnmarshalBinary", func(t *testing.T) {
		err := m.UnmarshalBinary(buf.Bytes())
		require.NoError(t, err)
		require.Equal(t, "hello world", m.DestinationName)
		require.Equal(t, "lorem ipsum", m.SourceName)
		require.Equal(t, []int16{int16(pgwire.FormatKindBinary), int16(pgwire.FormatKindBinary), int16(pgwire.FormatKindBinary)}, m.ParameterFormatCodes)
		require.Equal(t, [][]byte{[]byte("lorem"), []byte("ipsum"), []byte("dolor")}, m.ParameterData)
		require.Equal(t, []int16{int16(pgwire.FormatKindBinary), int16(pgwire.FormatKindBinary), int16(pgwire.FormatKindBinary)}, m.ColumnFormatCodes)
	})

	t.Run("AppendBinary", func(t *testing.T) {
		b, err := m.AppendBinary(nil)
		require.NoError(t, err)
		require.Equal(t, buf.Bytes(), b)
	})
}

func TestMsgCancelRequest(t *testing.T) {
	t.Parallel()

	buf := pgio.NewBuffer(nil)
	buf.AppendInt32(23)
	buf.AppendInt32(pgwire.CodeCancelRequest)
	buf.AppendInt32(4321)
	buf.AppendByte([]byte("hello world")...)

	var m pgwire.MsgCancelRequest

	t.Run("UnmarshalBinary", func(t *testing.T) {
		err := m.UnmarshalBinary(buf.Bytes())
		require.NoError(t, err)
		require.Equal(t, int32(4321), m.ProcessID)
		require.Equal(t, "hello world", string(m.SecretKey))
	})

	t.Run("AppendBinary", func(t *testing.T) {
		b, err := m.AppendBinary(nil)
		require.NoError(t, err)
		require.Equal(t, buf.Bytes(), b)
	})
}

func TestMsgClose(t *testing.T) {
	t.Parallel()

	buf := pgio.NewBuffer(nil)
	buf.AppendByte(byte(pgwire.MessageKindClose))
	buf.AppendInt32(17)
	buf.AppendByte('P')
	buf.AppendString("hello world")

	var m pgwire.MsgClose

	t.Run("UnmarshalBinary", func(t *testing.T) {
		err := m.UnmarshalBinary(buf.Bytes())
		require.NoError(t, err)
		require.Equal(t, uint8('P'), m.Kind)
		require.Equal(t, "hello world", m.Name)
	})

	t.Run("AppendBinary", func(t *testing.T) {
		b, err := m.AppendBinary(nil)
		require.NoError(t, err)
		require.Equal(t, buf.Bytes(), b)
	})
}

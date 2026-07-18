package pgwire_test

import (
	"gopsql/pgio"
	"gopsql/pgwire"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMsgBackendKeyData(t *testing.T) {
	t.Parallel()

	buf := pgio.NewBuffer(nil)
	buf.AppendByte(byte(pgwire.MessageKindBackendKeyData))
	buf.AppendInt32(19)
	buf.AppendInt32(4321)
	buf.AppendByte([]byte("hello world")...)

	var m pgwire.MsgBackendKeyData

	unmarshalTest(t, buf.Bytes(), &m, func(t *testing.T, m *pgwire.MsgBackendKeyData) {
		require.Equal(t, int32(4321), m.ProcessID)
		require.Equal(t, "hello world", string(m.SecretKey))
	})

	appendTest(t, &m, buf.Bytes())
}

func TestMsgBindComplete(t *testing.T) {
	t.Parallel()

	buf := pgio.NewBuffer(nil)
	buf.AppendByte(byte(pgwire.MessageKindBindComplete))
	buf.AppendInt32(4)

	var m pgwire.MsgBindComplete

	t.Run("UnmarshalBinary", func(t *testing.T) {
		err := m.UnmarshalBinary(buf.Bytes())
		require.NoError(t, err)
	})

	t.Run("AppendBinary", func(t *testing.T) {
		b, err := m.AppendBinary(nil)
		require.NoError(t, err)
		require.Equal(t, buf.Bytes(), b)
	})
}

func TestMsgCloseComplete(t *testing.T) {
	t.Parallel()

	buf := pgio.NewBuffer(nil)
	buf.AppendByte(byte(pgwire.MessageKindCloseComplete))
	buf.AppendInt32(4)

	var m pgwire.MsgCloseComplete

	t.Run("UnmarshalBinary", func(t *testing.T) {
		err := m.UnmarshalBinary(buf.Bytes())
		require.NoError(t, err)
	})

	t.Run("AppendBinary", func(t *testing.T) {
		b, err := m.AppendBinary(nil)
		require.NoError(t, err)
		require.Equal(t, buf.Bytes(), b)
	})
}

func TestMsgCommandComplete(t *testing.T) {
	t.Parallel()

	buf := pgio.NewBuffer(nil)
	buf.AppendByte(byte(pgwire.MessageKindCommandComplete))
	buf.AppendInt32(16)
	buf.AppendString("hello world")

	var m pgwire.MsgCommandComplete

	t.Run("UnmarshalBinary", func(t *testing.T) {
		err := m.UnmarshalBinary(buf.Bytes())
		require.NoError(t, err)
		require.Equal(t, "hello world", m.Tag)
	})

	t.Run("AppendBinary", func(t *testing.T) {
		b, err := m.AppendBinary(nil)
		require.NoError(t, err)
		require.Equal(t, buf.Bytes(), b)
	})
}

func TestMsgCopyInResponse(t *testing.T) {
	t.Parallel()

	buf := pgio.NewBuffer(nil)
	buf.AppendByte(byte(pgwire.MessageKindCopyInResponse))
	buf.AppendInt32(13)
	buf.AppendInt8(int8(pgwire.FormatKindBinary))
	buf.AppendInt16(3)
	buf.AppendInt16(int16(pgwire.FormatKindBinary))
	buf.AppendInt16(int16(pgwire.FormatKindBinary))
	buf.AppendInt16(int16(pgwire.FormatKindBinary))

	var m pgwire.MsgCopyInResponse

	t.Run("UnmarshalBinary", func(t *testing.T) {
		err := m.UnmarshalBinary(buf.Bytes())
		require.NoError(t, err)
		require.Equal(t, int8(pgwire.FormatKindBinary), m.Format)
		require.Equal(t, []int16{
			int16(pgwire.FormatKindBinary),
			int16(pgwire.FormatKindBinary),
			int16(pgwire.FormatKindBinary),
		}, m.Columns)
	})

	t.Run("AppendBinary", func(t *testing.T) {
		b, err := m.AppendBinary(nil)
		require.NoError(t, err)
		require.Equal(t, buf.Bytes(), b)
	})
}

func TestMsgCopyOutResponse(t *testing.T) {
	t.Parallel()

	buf := pgio.NewBuffer(nil)
	buf.AppendByte(byte(pgwire.MessageKindCopyOutResponse))
	buf.AppendInt32(13)
	buf.AppendInt8(int8(pgwire.FormatKindBinary))
	buf.AppendInt16(3)
	buf.AppendInt16(int16(pgwire.FormatKindBinary))
	buf.AppendInt16(int16(pgwire.FormatKindBinary))
	buf.AppendInt16(int16(pgwire.FormatKindBinary))

	var m pgwire.MsgCopyOutResponse

	t.Run("UnmarshalBinary", func(t *testing.T) {
		err := m.UnmarshalBinary(buf.Bytes())
		require.NoError(t, err)
		require.Equal(t, int8(pgwire.FormatKindBinary), m.Format)
		require.Equal(t, []int16{
			int16(pgwire.FormatKindBinary),
			int16(pgwire.FormatKindBinary),
			int16(pgwire.FormatKindBinary),
		}, m.Columns)
	})

	t.Run("AppendBinary", func(t *testing.T) {
		b, err := m.AppendBinary(nil)
		require.NoError(t, err)
		require.Equal(t, buf.Bytes(), b)
	})
}

func TestMsgCopyBothResponse(t *testing.T) {
	t.Parallel()

	buf := pgio.NewBuffer(nil)
	buf.AppendByte(byte(pgwire.MessageKindCopyBothResponse))
	buf.AppendInt32(13)
	buf.AppendInt8(int8(pgwire.FormatKindBinary))
	buf.AppendInt16(3)
	buf.AppendInt16(int16(pgwire.FormatKindBinary))
	buf.AppendInt16(int16(pgwire.FormatKindBinary))
	buf.AppendInt16(int16(pgwire.FormatKindBinary))

	var m pgwire.MsgCopyBothResponse

	t.Run("UnmarshalBinary", func(t *testing.T) {
		err := m.UnmarshalBinary(buf.Bytes())
		require.NoError(t, err)
		require.Equal(t, int8(pgwire.FormatKindBinary), m.Format)
		require.Equal(t, []int16{
			int16(pgwire.FormatKindBinary),
			int16(pgwire.FormatKindBinary),
			int16(pgwire.FormatKindBinary),
		}, m.Columns)
	})

	t.Run("AppendBinary", func(t *testing.T) {
		b, err := m.AppendBinary(nil)
		require.NoError(t, err)
		require.Equal(t, buf.Bytes(), b)
	})
}

func TestMsgDataRow(t *testing.T) {
	t.Parallel()

	buf := pgio.NewBuffer(nil)
	buf.AppendByte(byte(pgwire.MessageKindDataRow))
	buf.AppendInt32(28)
	buf.AppendInt16(3)
	buf.AppendInt32(5)
	buf.AppendByte([]byte("hello")...)
	buf.AppendInt32(-1)
	buf.AppendInt32(5)
	buf.AppendByte([]byte("world")...)

	var m pgwire.MsgDataRow

	t.Run("UnmarshalBinary", func(t *testing.T) {
		err := m.UnmarshalBinary(buf.Bytes())
		require.NoError(t, err)
		require.Len(t, m.Columns, 3)
		require.Equal(t, []byte("hello"), m.Columns[0])
		require.Nil(t, m.Columns[1])
		require.Equal(t, []byte("world"), m.Columns[2])
	})

	t.Run("AppendBinary", func(t *testing.T) {
		b, err := m.AppendBinary(nil)
		require.NoError(t, err)
		require.Equal(t, buf.Bytes(), b)
	})
}

func TestMsgEmptyQueryResponse(t *testing.T) {
	t.Parallel()

	buf := pgio.NewBuffer(nil)
	buf.AppendByte(byte(pgwire.MessageKindEmptyQueryResponse))
	buf.AppendInt32(4)

	var m pgwire.MsgEmptyQueryResponse

	t.Run("UnmarshalBinary", func(t *testing.T) {
		err := m.UnmarshalBinary(buf.Bytes())
		require.NoError(t, err)
	})

	t.Run("AppendBinary", func(t *testing.T) {
		b, err := m.AppendBinary(nil)
		require.NoError(t, err)
		require.Equal(t, buf.Bytes(), b)
	})
}

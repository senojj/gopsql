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

	testMessage(t, buf.Bytes(), &m, func(t *testing.T) {
		require.Equal(t, int32(4321), m.ProcessID)
		require.Equal(t, "hello world", string(m.SecretKey))
	})
}

func TestMsgBindComplete(t *testing.T) {
	t.Parallel()

	buf := pgio.NewBuffer(nil)
	buf.AppendByte(byte(pgwire.MessageKindBindComplete))
	buf.AppendInt32(4)

	var m pgwire.MsgBindComplete

	testMessage(t, buf.Bytes(), &m, nil)
}

func TestMsgCloseComplete(t *testing.T) {
	t.Parallel()

	buf := pgio.NewBuffer(nil)
	buf.AppendByte(byte(pgwire.MessageKindCloseComplete))
	buf.AppendInt32(4)

	var m pgwire.MsgCloseComplete

	testMessage(t, buf.Bytes(), &m, nil)
}

func TestMsgCommandComplete(t *testing.T) {
	t.Parallel()

	buf := pgio.NewBuffer(nil)
	buf.AppendByte(byte(pgwire.MessageKindCommandComplete))
	buf.AppendInt32(16)
	buf.AppendString("hello world")

	var m pgwire.MsgCommandComplete

	testMessage(t, buf.Bytes(), &m, func(t *testing.T) {
		require.Equal(t, "hello world", m.Tag)
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

	testMessage(t, buf.Bytes(), &m, func(t *testing.T) {
		require.Equal(t, int8(pgwire.FormatKindBinary), m.Format)
		require.Equal(t, []int16{
			int16(pgwire.FormatKindBinary),
			int16(pgwire.FormatKindBinary),
			int16(pgwire.FormatKindBinary),
		}, m.Columns)
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

	testMessage(t, buf.Bytes(), &m, func(t *testing.T) {
		require.Equal(t, int8(pgwire.FormatKindBinary), m.Format)
		require.Equal(t, []int16{
			int16(pgwire.FormatKindBinary),
			int16(pgwire.FormatKindBinary),
			int16(pgwire.FormatKindBinary),
		}, m.Columns)
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

	testMessage(t, buf.Bytes(), &m, func(t *testing.T) {
		require.Equal(t, int8(pgwire.FormatKindBinary), m.Format)
		require.Equal(t, []int16{
			int16(pgwire.FormatKindBinary),
			int16(pgwire.FormatKindBinary),
			int16(pgwire.FormatKindBinary),
		}, m.Columns)
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

	testMessage(t, buf.Bytes(), &m, func(t *testing.T) {
		require.Len(t, m.Columns, 3)
		require.Equal(t, []byte("hello"), m.Columns[0])
		require.Nil(t, m.Columns[1])
		require.Equal(t, []byte("world"), m.Columns[2])
	})
}

func TestMsgEmptyQueryResponse(t *testing.T) {
	t.Parallel()

	buf := pgio.NewBuffer(nil)
	buf.AppendByte(byte(pgwire.MessageKindEmptyQueryResponse))
	buf.AppendInt32(4)

	var m pgwire.MsgEmptyQueryResponse

	testMessage(t, buf.Bytes(), &m, nil)
}

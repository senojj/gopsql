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
	buf.AppendInt16(
		int16(pgwire.FormatKindBinary),
		int16(pgwire.FormatKindBinary),
		int16(pgwire.FormatKindBinary),
	)
	buf.AppendInt16(3)
	buf.AppendInt32(5)
	buf.AppendByte([]byte("lorem")...)
	buf.AppendInt32(5)
	buf.AppendByte([]byte("ipsum")...)
	buf.AppendInt32(5)
	buf.AppendByte([]byte("dolor")...)
	buf.AppendInt16(3)
	buf.AppendInt16(
		int16(pgwire.FormatKindBinary),
		int16(pgwire.FormatKindBinary),
		int16(pgwire.FormatKindBinary),
	)

	var m pgwire.MsgBind

	testMessage(t, buf.Bytes(), &m, func(t *testing.T) {
		require.Equal(t, "hello world", m.DestinationName)

		require.Equal(t, "lorem ipsum", m.SourceName)

		require.Equal(t, []pgwire.FormatKind{
			pgwire.FormatKindBinary,
			pgwire.FormatKindBinary,
			pgwire.FormatKindBinary,
		}, m.ParameterFormatCodes)

		require.Equal(t, [][]byte{
			[]byte("lorem"),
			[]byte("ipsum"),
			[]byte("dolor"),
		}, m.ParameterData)

		require.Equal(t, []pgwire.FormatKind{
			pgwire.FormatKindBinary,
			pgwire.FormatKindBinary,
			pgwire.FormatKindBinary,
		}, m.ColumnFormatCodes)
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

	testMessage(t, buf.Bytes(), &m, func(t *testing.T) {
		require.Equal(t, int32(4321), m.ProcessID)
		require.Equal(t, "hello world", string(m.SecretKey))
	})
}

func TestMsgClose(t *testing.T) {
	t.Parallel()

	buf := pgio.NewBuffer(nil)
	buf.AppendByte(byte(pgwire.MessageKindClose))
	buf.AppendInt32(17)
	buf.AppendInt8(int8(pgwire.ObjectKindPortal))
	buf.AppendString("hello world")

	var m pgwire.MsgClose

	testMessage(t, buf.Bytes(), &m, func(t *testing.T) {
		require.Equal(t, pgwire.ObjectKindPortal, m.ObjectKind)
		require.Equal(t, "hello world", m.ObjectName)
	})
}

func TestMsgCopyFail(t *testing.T) {
	t.Parallel()

	buf := pgio.NewBuffer(nil)
	buf.AppendByte(byte(pgwire.MessageKindCopyFail))
	buf.AppendInt32(16)
	buf.AppendString("hello world")

	var m pgwire.MsgCopyFail

	testMessage(t, buf.Bytes(), &m, func(t *testing.T) {
		require.Equal(t, "hello world", m.Message)
	})
}

func TestMsgDescribe(t *testing.T) {
	t.Parallel()

	buf := pgio.NewBuffer(nil)
	buf.AppendByte(byte(pgwire.MessageKindDescribe))
	buf.AppendInt32(17)
	buf.AppendByte(byte(pgwire.ObjectKindPortal))
	buf.AppendString("hello world")

	var m pgwire.MsgDescribe

	testMessage(t, buf.Bytes(), &m, func(t *testing.T) {
		require.Equal(t, pgwire.ObjectKindPortal, m.ObjectKind)
		require.Equal(t, "hello world", m.ObjectName)
	})
}

func TestMsgExecute(t *testing.T) {
	t.Parallel()

	buf := pgio.NewBuffer(nil)
	buf.AppendByte(byte(pgwire.MessageKindExecute))
	buf.AppendInt32(20)
	buf.AppendString("hello world")
	buf.AppendInt32(5)

	var m pgwire.MsgExecute

	testMessage(t, buf.Bytes(), &m, func(t *testing.T) {
		require.Equal(t, "hello world", m.PortalName)
		require.Equal(t, int32(5), m.RowLimit)
	})
}

func TestMsgFlush(t *testing.T) {
	t.Parallel()

	buf := pgio.NewBuffer(nil)
	buf.AppendByte(byte(pgwire.MessageKindFlush))
	buf.AppendInt32(4)

	var m pgwire.MsgFlush

	testMessage(t, buf.Bytes(), &m, nil)
}

func TestMsgFunctionCall(t *testing.T) {
	t.Parallel()

	buf := pgio.NewBuffer(nil)
	buf.AppendByte(byte(pgwire.MessageKindFunctionCall))
	buf.AppendInt32(39)
	buf.AppendInt32(4321)
	buf.AppendInt16(1)
	buf.AppendInt16(int16(pgwire.FormatKindBinary))
	buf.AppendInt16(3)
	buf.AppendInt32(5)
	buf.AppendByte([]byte("hello")...)
	buf.AppendInt32(1)
	buf.AppendByte([]byte(" ")...)
	buf.AppendInt32(5)
	buf.AppendByte([]byte("world")...)
	buf.AppendInt16(int16(pgwire.FormatKindBinary))

	var m pgwire.MsgFunctionCall

	testMessage(t, buf.Bytes(), &m, func(t *testing.T) {
		require.Equal(t, int32(4321), m.ObjectID)
		require.Len(t, m.ArgumentFormats, 1)
		require.Equal(t, []pgwire.FormatKind{pgwire.FormatKindBinary}, m.ArgumentFormats)
		require.Len(t, m.ArgumentValues, 3)
		require.Equal(t, [][]byte{
			[]byte("hello"),
			[]byte(" "),
			[]byte("world"),
		}, m.ArgumentValues)
		require.Equal(t, pgwire.FormatKindBinary, m.ResultFormat)
	})
}

package pgwire_test

import (
	"gopsql/pgio"
	"gopsql/pgwire"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMsgCopyData(t *testing.T) {
	t.Parallel()

	buf := pgio.NewBuffer(nil)
	buf.AppendByte(byte(pgwire.MessageKindCopyData))
	buf.AppendInt32(15)
	buf.AppendByte([]byte("hello world")...)

	var m pgwire.MsgCopyData

	testMessage(t, buf.Bytes(), &m, func(t *testing.T) {
		require.Equal(t, []byte("hello world"), m.Data)
	})
}

func TestMsgCopyDone(t *testing.T) {
	t.Parallel()

	buf := pgio.NewBuffer(nil)
	buf.AppendByte(byte(pgwire.MessageKindCopyDone))
	buf.AppendInt32(4)

	var m pgwire.MsgCopyDone

	testMessage(t, buf.Bytes(), &m, nil)
}

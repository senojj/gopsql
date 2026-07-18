package pgwire_test

import (
	"gopsql/pgio"
	"gopsql/pgwire"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMsgAuthenticationOk(t *testing.T) {
	t.Parallel()

	buf := pgio.NewBuffer(nil)
	buf.AppendByte(byte(pgwire.MessageKindAuthentication))
	buf.AppendInt32(8)
	buf.AppendInt32(int32(pgwire.AuthenticationKindOk))

	var m pgwire.MsgAuthenticationOk

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

func TestMsgAuthenticationKerberosV5(t *testing.T) {
	t.Parallel()

	buf := pgio.NewBuffer(nil)
	buf.AppendByte(byte(pgwire.MessageKindAuthentication))
	buf.AppendInt32(8)
	buf.AppendInt32(int32(pgwire.AuthenticationKindKerberosV5))

	var m pgwire.MsgAuthenticationKerberosV5

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

func TestMsgAuthenticationClearTextPassword(t *testing.T) {
	t.Parallel()

	buf := pgio.NewBuffer(nil)
	buf.AppendByte(byte(pgwire.MessageKindAuthentication))
	buf.AppendInt32(8)
	buf.AppendInt32(int32(pgwire.AuthenticationKindClearTextPassword))

	var m pgwire.MsgAuthenticationCleartextPassword

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

func TestMsgAuthenticationMD5Password(t *testing.T) {
	t.Parallel()

	buf := pgio.NewBuffer(nil)
	buf.AppendByte(byte(pgwire.MessageKindAuthentication))
	buf.AppendInt32(12)
	buf.AppendInt32(int32(pgwire.AuthenticationKindMD5Password))
	buf.AppendByte([]byte("4321")...)

	var m pgwire.MsgAuthenticationMD5Password

	t.Run("UnmarshalBinary", func(t *testing.T) {
		err := m.UnmarshalBinary(buf.Bytes())
		require.NoError(t, err)
		require.Equal(t, "4321", string(m.Salt[:]))
	})

	t.Run("AppendBinary", func(t *testing.T) {
		b, err := m.AppendBinary(nil)
		require.NoError(t, err)
		require.Equal(t, buf.Bytes(), b)
	})
}

func TestMsgAuthenticationGSS(t *testing.T) {
	t.Parallel()

	buf := pgio.NewBuffer(nil)
	buf.AppendByte(byte(pgwire.MessageKindAuthentication))
	buf.AppendInt32(8)
	buf.AppendInt32(int32(pgwire.AuthenticationKindGSS))

	var m pgwire.MsgAuthenticationGSS

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

func TestMsgAuthenticationGSSContinue(t *testing.T) {
	t.Parallel()

	buf := pgio.NewBuffer(nil)
	buf.AppendByte(byte(pgwire.MessageKindAuthentication))
	buf.AppendInt32(19)
	buf.AppendInt32(int32(pgwire.AuthenticationKindGSSContinue))
	buf.AppendByte([]byte("hello world")...)

	var m pgwire.MsgAuthenticationGSSContinue

	t.Run("UnmarshalBinary", func(t *testing.T) {
		err := m.UnmarshalBinary(buf.Bytes())
		require.NoError(t, err)

		require.Equal(t, "hello world", string(m.Data))
	})

	t.Run("AppendBinary", func(t *testing.T) {
		b, err := m.AppendBinary(nil)
		require.NoError(t, err)
		require.Equal(t, buf.Bytes(), b)
	})
}

func TestMsgAuthenticationSSPI(t *testing.T) {
	t.Parallel()

	buf := pgio.NewBuffer(nil)
	buf.AppendByte(byte(pgwire.MessageKindAuthentication))
	buf.AppendInt32(8)
	buf.AppendInt32(int32(pgwire.AuthenticationKindSSPI))

	var m pgwire.MsgAuthenticationSSPI

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

func TestMsgAuthenticationSASL(t *testing.T) {
	t.Parallel()

	buf := pgio.NewBuffer(nil)
	buf.AppendByte(byte(pgwire.MessageKindAuthentication))
	buf.AppendInt32(21)
	buf.AppendInt32(int32(pgwire.AuthenticationKindSASL))
	buf.AppendString("hello", "world")
	buf.AppendByte(0)

	var m pgwire.MsgAuthenticationSASL

	t.Run("UnmarshalBinary", func(t *testing.T) {
		err := m.UnmarshalBinary(buf.Bytes())
		require.NoError(t, err)
		require.Equal(t, []string{"hello", "world"}, m.Mechanisms)
	})

	t.Run("AppendBinary", func(t *testing.T) {
		b, err := m.AppendBinary(nil)
		require.NoError(t, err)
		require.Equal(t, buf.Bytes(), b)
	})
}

func TestMsgAuthenticationSASLContinue(t *testing.T) {
	t.Parallel()

	buf := pgio.NewBuffer(nil)
	buf.AppendByte(byte(pgwire.MessageKindAuthentication))
	buf.AppendInt32(19)
	buf.AppendInt32(int32(pgwire.AuthenticationKindSASLContinue))
	buf.AppendByte([]byte("hello world")...)

	var m pgwire.MsgAuthenticationSASLContinue

	t.Run("UnmarshalBinary", func(t *testing.T) {
		err := m.UnmarshalBinary(buf.Bytes())
		require.NoError(t, err)
		require.Equal(t, "hello world", string(m.Data))
	})

	t.Run("AppendBinary", func(t *testing.T) {
		b, err := m.AppendBinary(nil)
		require.NoError(t, err)
		require.Equal(t, buf.Bytes(), b)
	})
}

func TestMsgAuthenticationSASLFinal(t *testing.T) {
	t.Parallel()

	buf := pgio.NewBuffer(nil)
	buf.AppendByte(byte(pgwire.MessageKindAuthentication))
	buf.AppendInt32(19)
	buf.AppendInt32(int32(pgwire.AuthenticationKindSASLFinal))
	buf.AppendByte([]byte("hello world")...)

	var m pgwire.MsgAuthenticationSASLFinal

	t.Run("UnmarshalBinary", func(t *testing.T) {
		err := m.UnmarshalBinary(buf.Bytes())
		require.NoError(t, err)
		require.Equal(t, "hello world", string(m.Data))
	})

	t.Run("AppendBinary", func(t *testing.T) {
		b, err := m.AppendBinary(nil)
		require.NoError(t, err)
		require.Equal(t, buf.Bytes(), b)
	})
}

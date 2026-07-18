package pgwire

import (
	"gopsql/pgio"
	"math"
)

var _ Message = &MsgAuthenticationOk{}
var _ Backend = &MsgAuthenticationOk{}

type MsgAuthenticationOk struct{}

func (x *MsgAuthenticationOk) message() {}

func (x *MsgAuthenticationOk) backend() {}

func (x *MsgAuthenticationOk) AppendBinary(b []byte) ([]byte, error) {
	const length = sizeMessageLength + sizeAuthKind
	const size = sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(byte(MessageKindAuthentication))
	buf.AppendInt32(int32(length))
	buf.AppendInt32(int32(AuthenticationKindOk))
	return buf.Bytes(), nil
}

func (x *MsgAuthenticationOk) UnmarshalBinary(b []byte) error {
	b, err := shiftHeader(MessageKindAuthentication, b)
	if err != nil {
		return invalidFormat(err)
	}

	authKind, b, err := pgio.ShiftInt32(b)
	if err != nil {
		return invalidFormat(err)
	}

	if !AuthenticationKindOk.Is(authKind) {
		return unexpectedAuthKind(authKind, AuthenticationKindOk)
	}

	if len(b) > 0 {
		return pgio.ErrValueOverflow
	}
	return nil
}

var _ Message = &MsgAuthenticationKerberosV5{}
var _ Backend = &MsgAuthenticationKerberosV5{}

type MsgAuthenticationKerberosV5 struct{}

func (x *MsgAuthenticationKerberosV5) message() {}

func (x *MsgAuthenticationKerberosV5) backend() {}

func (x *MsgAuthenticationKerberosV5) AppendBinary(b []byte) ([]byte, error) {
	const length = sizeMessageLength + sizeAuthKind
	const size = sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(byte(MessageKindAuthentication))
	buf.AppendInt32(int32(length))
	buf.AppendInt32(int32(AuthenticationKindKerberosV5))
	return buf.Bytes(), nil
}

func (x *MsgAuthenticationKerberosV5) UnmarshalBinary(b []byte) error {
	b, err := shiftHeader(MessageKindAuthentication, b)
	if err != nil {
		return invalidFormat(err)
	}

	authKind, b, err := pgio.ShiftInt32(b)
	if err != nil {
		return invalidFormat(err)
	}

	if !AuthenticationKindKerberosV5.Is(authKind) {
		return unexpectedAuthKind(authKind, AuthenticationKindKerberosV5)
	}

	if len(b) > 0 {
		return invalidFormat(pgio.ErrValueOverflow)
	}
	return nil
}

var _ Message = &MsgAuthenticationCleartextPassword{}
var _ Backend = &MsgAuthenticationCleartextPassword{}

type MsgAuthenticationCleartextPassword struct{}

func (x *MsgAuthenticationCleartextPassword) message() {}

func (x *MsgAuthenticationCleartextPassword) backend() {}

func (x *MsgAuthenticationCleartextPassword) AppendBinary(b []byte) ([]byte, error) {
	const length = sizeMessageLength + sizeAuthKind
	const size = sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(byte(MessageKindAuthentication))
	buf.AppendInt32(int32(length))
	buf.AppendInt32(int32(AuthenticationKindClearTextPassword))
	return buf.Bytes(), nil
}

func (x *MsgAuthenticationCleartextPassword) UnmarshalBinary(b []byte) error {
	b, err := shiftHeader(MessageKindAuthentication, b)
	if err != nil {
		return invalidFormat(err)
	}

	authKind, b, err := pgio.ShiftInt32(b)
	if err != nil {
		return invalidFormat(err)
	}

	if !AuthenticationKindClearTextPassword.Is(authKind) {
		return unexpectedAuthKind(authKind, AuthenticationKindClearTextPassword)
	}

	if len(b) > 0 {
		return invalidFormat(pgio.ErrValueOverflow)
	}
	return nil
}

var _ Message = &MsgAuthenticationMD5Password{}
var _ Backend = &MsgAuthenticationMD5Password{}

type MsgAuthenticationMD5Password struct {
	Salt [4]byte
}

func (x *MsgAuthenticationMD5Password) message() {}

func (x *MsgAuthenticationMD5Password) backend() {}

func (x *MsgAuthenticationMD5Password) AppendBinary(b []byte) ([]byte, error) {
	const sizeSalt = 4
	const length = sizeMessageLength + sizeAuthKind + sizeSalt
	const size = sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(byte(MessageKindAuthentication))
	buf.AppendInt32(int32(length))
	buf.AppendInt32(int32(AuthenticationKindMD5Password))
	buf.AppendByte(x.Salt[:]...)
	return buf.Bytes(), nil
}

func (x *MsgAuthenticationMD5Password) UnmarshalBinary(b []byte) error {
	b, err := shiftHeader(MessageKindAuthentication, b)
	if err != nil {
		return invalidFormat(err)
	}

	authKind, b, err := pgio.ShiftInt32(b)
	if err != nil {
		return invalidFormat(err)
	}

	if !AuthenticationKindMD5Password.Is(authKind) {
		return unexpectedAuthKind(authKind, AuthenticationKindMD5Password)
	}
	copy(x.Salt[:], b)
	return nil
}

var _ Message = &MsgAuthenticationGSS{}
var _ Backend = &MsgAuthenticationGSS{}

type MsgAuthenticationGSS struct{}

func (x *MsgAuthenticationGSS) message() {}

func (x *MsgAuthenticationGSS) backend() {}

func (x *MsgAuthenticationGSS) AppendBinary(b []byte) ([]byte, error) {
	const length = sizeMessageLength + sizeAuthKind
	const size = sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(byte(MessageKindAuthentication))
	buf.AppendInt32(int32(length))
	buf.AppendInt32(int32(AuthenticationKindGSS))
	return buf.Bytes(), nil
}

func (x *MsgAuthenticationGSS) UnmarshalBinary(b []byte) error {
	b, err := shiftHeader(MessageKindAuthentication, b)
	if err != nil {
		return invalidFormat(err)
	}

	authKind, b, err := pgio.ShiftInt32(b)
	if err != nil {
		return invalidFormat(err)
	}

	if !AuthenticationKindGSS.Is(authKind) {
		return unexpectedAuthKind(authKind, AuthenticationKindGSS)
	}
	if len(b) > 0 {
		return invalidFormat(pgio.ErrValueOverflow)
	}
	return nil
}

var _ Message = &MsgAuthenticationGSSContinue{}
var _ Backend = &MsgAuthenticationGSSContinue{}

type MsgAuthenticationGSSContinue struct {
	Data []byte
}

func (x *MsgAuthenticationGSSContinue) message() {}

func (x *MsgAuthenticationGSSContinue) backend() {}

func (x *MsgAuthenticationGSSContinue) AppendBinary(b []byte) ([]byte, error) {
	sizeData := len(x.Data)
	length := sizeMessageLength + sizeAuthKind + sizeData

	if length > math.MaxInt32 {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(byte(MessageKindAuthentication))
	buf.AppendInt32(int32(length))
	buf.AppendInt32(int32(AuthenticationKindGSSContinue))
	buf.AppendByte(x.Data...)
	return buf.Bytes(), nil
}

func (x *MsgAuthenticationGSSContinue) UnmarshalBinary(b []byte) error {
	b, err := shiftHeader(MessageKindAuthentication, b)
	if err != nil {
		return invalidFormat(err)
	}

	authKind, b, err := pgio.ShiftInt32(b)
	if err != nil {
		return invalidFormat(err)
	}

	if !AuthenticationKindGSSContinue.Is(authKind) {
		return unexpectedAuthKind(authKind, AuthenticationKindGSSContinue)
	}
	x.Data = make([]byte, len(b))
	copy(x.Data, b)
	return nil
}

var _ Message = &MsgAuthenticationSSPI{}
var _ Backend = &MsgAuthenticationSSPI{}

type MsgAuthenticationSSPI struct{}

func (x *MsgAuthenticationSSPI) message() {}

func (x *MsgAuthenticationSSPI) backend() {}

func (x *MsgAuthenticationSSPI) AppendBinary(b []byte) ([]byte, error) {
	const length = sizeMessageLength + sizeAuthKind
	const size = sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(byte(MessageKindAuthentication))
	buf.AppendInt32(int32(length))
	buf.AppendInt32(int32(AuthenticationKindSSPI))
	return buf.Bytes(), nil
}

func (x *MsgAuthenticationSSPI) UnmarshalBinary(b []byte) error {
	b, err := shiftHeader(MessageKindAuthentication, b)
	if err != nil {
		return invalidFormat(err)
	}

	authKind, b, err := pgio.ShiftInt32(b)
	if err != nil {
		return invalidFormat(err)
	}

	if !AuthenticationKindSSPI.Is(authKind) {
		return unexpectedAuthKind(authKind, AuthenticationKindSSPI)
	}

	if len(b) > 0 {
		return invalidFormat(pgio.ErrValueOverflow)
	}
	return nil
}

var _ Message = &MsgAuthenticationSASL{}
var _ Backend = &MsgAuthenticationSASL{}

type MsgAuthenticationSASL struct {
	Mechanisms []string
}

func (x *MsgAuthenticationSASL) message() {}

func (x *MsgAuthenticationSASL) backend() {}

func (x *MsgAuthenticationSASL) AppendBinary(b []byte) ([]byte, error) {
	countMechanisms := len(x.Mechanisms)
	sizeMechanisms := 0

	for i := range countMechanisms {
		sizeMechanisms += len(x.Mechanisms[i]) + 1 // null terminated string
	}
	sizeMechanisms += 1 // null terminated list

	length := sizeMessageLength + sizeAuthKind + sizeMechanisms

	if length > math.MaxInt32 {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(byte(MessageKindAuthentication))
	buf.AppendInt32(int32(length))
	buf.AppendInt32(int32(AuthenticationKindSASL))
	buf.AppendString(x.Mechanisms...)
	buf.AppendByte(0x0)
	return buf.Bytes(), nil
}

func (x *MsgAuthenticationSASL) UnmarshalBinary(b []byte) error {
	b, err := shiftHeader(MessageKindAuthentication, b)
	if err != nil {
		return invalidFormat(err)
	}

	buf := pgio.NewBuffer(b)

	authKind, err := buf.ShiftInt32()
	if err != nil {
		return invalidFormat(err)
	}

	if !AuthenticationKindSASL.Is(authKind) {
		return unexpectedAuthKind(authKind, AuthenticationKindSASL)
	}
	x.Mechanisms = make([]string, 0, buf.Count(nullByte))

	for {
		var mechanism string
		var err error

		mechanism, err = buf.ShiftString()
		if err != nil {
			return invalidFormat(err)
		}

		if len(mechanism) == 0 {
			break
		}
		x.Mechanisms = append(x.Mechanisms, mechanism)
	}
	return nil
}

var _ Message = &MsgAuthenticationSASLContinue{}
var _ Backend = &MsgAuthenticationSASLContinue{}

type MsgAuthenticationSASLContinue struct {
	Data []byte
}

func (x *MsgAuthenticationSASLContinue) message() {}

func (x *MsgAuthenticationSASLContinue) backend() {}

func (x *MsgAuthenticationSASLContinue) AppendBinary(b []byte) ([]byte, error) {
	sizeData := len(x.Data)

	length := sizeMessageLength + sizeAuthKind + sizeData

	if length > math.MaxInt32 {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(byte(MessageKindAuthentication))
	buf.AppendInt32(int32(length))
	buf.AppendInt32(int32(AuthenticationKindSASLContinue))
	buf.AppendByte(x.Data...)
	return buf.Bytes(), nil
}

func (x *MsgAuthenticationSASLContinue) UnmarshalBinary(b []byte) error {
	b, err := shiftHeader(MessageKindAuthentication, b)
	if err != nil {
		return invalidFormat(err)
	}

	authKind, b, err := pgio.ShiftInt32(b)
	if err != nil {
		return invalidFormat(err)
	}

	if !AuthenticationKindSASLContinue.Is(authKind) {
		return unexpectedAuthKind(authKind, AuthenticationKindSASLContinue)
	}
	x.Data = make([]byte, len(b))
	copy(x.Data, b)
	return nil
}

var _ Message = &MsgAuthenticationSASLFinal{}
var _ Backend = &MsgAuthenticationSASLFinal{}

type MsgAuthenticationSASLFinal struct {
	Data []byte
}

func (x *MsgAuthenticationSASLFinal) message() {}

func (x *MsgAuthenticationSASLFinal) backend() {}

func (x *MsgAuthenticationSASLFinal) AppendBinary(b []byte) ([]byte, error) {
	sizeData := len(x.Data)

	length := sizeMessageLength + sizeAuthKind + sizeData

	if length > math.MaxInt32 {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(byte(MessageKindAuthentication))
	buf.AppendInt32(int32(length))
	buf.AppendInt32(int32(AuthenticationKindSASLFinal))
	buf.AppendByte(x.Data...)
	return buf.Bytes(), nil
}

func (x *MsgAuthenticationSASLFinal) UnmarshalBinary(b []byte) error {
	b, err := shiftHeader(MessageKindAuthentication, b)
	if err != nil {
		return invalidFormat(err)
	}

	authKind, b, err := pgio.ShiftInt32(b)
	if err != nil {
		return invalidFormat(err)
	}

	if !AuthenticationKindSASLFinal.Is(authKind) {
		return unexpectedAuthKind(authKind, AuthenticationKindSASLFinal)
	}
	x.Data = make([]byte, len(b))
	copy(x.Data, b)
	return nil
}

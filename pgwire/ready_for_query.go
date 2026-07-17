package pgwire

import (
	"gopsql/pgio"
)

var _ Message = &ReadyForQuery{}
var _ Backend = &ReadyForQuery{}

type ReadyForQuery struct {
	TxStatus byte
}

func (x *ReadyForQuery) message() {}

func (x *ReadyForQuery) backend() {}

func (x *ReadyForQuery) AppendBinary(b []byte) ([]byte, error) {
	const sizeTxStatus = 1
	const length = sizeMessageLength + sizeTxStatus
	const size = sizeMessageKind + length

	buf := pgio.NewBuffer(b)

	buf.Grow(size)
	buf.AppendByte(byte(MsgReadyForQuery))
	buf.AppendInt32(int32(length))
	buf.AppendByte(x.TxStatus)
	return buf.Bytes(), nil
}

func (x *ReadyForQuery) UnmarshalBinary(b []byte) error {
	b, err := ShiftHeader(MsgReadyForQuery, b)
	if err != nil {
		return invalidFormat(err)
	}

	status, b, err := pgio.ShiftByte(b)
	if err != nil {
		return invalidFormat(err)
	}

	if len(b) > 0 {
		return invalidFormat(pgio.ErrValueOverflow)
	}

	x.TxStatus = status
	return nil
}

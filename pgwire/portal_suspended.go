package pgwire

import "gopsql/pgio"

var _ Message = &PortalSuspended{}
var _ Backend = &PortalSuspended{}

type PortalSuspended struct{}

func (x *PortalSuspended) message() {}

func (x *PortalSuspended) backend() {}

func (x *PortalSuspended) AppendBinary(b []byte) ([]byte, error) {
	const length = sizeMessageLength
	const size = sizeMessageKind + length

	buf := pgio.NewBuffer(b)

	buf.Grow(size)
	buf.AppendByte(byte(MsgPortalSuspend))
	buf.AppendInt32(int32(length))
	return buf.Bytes(), nil
}

func (x *PortalSuspended) UnmarshalBinary(b []byte) error {
	b, err := ShiftHeader(MsgPortalSuspend, b)
	if err != nil {
		return invalidFormat(err)
	}

	if len(b) > 0 {
		return invalidFormat(pgio.ErrValueOverflow)
	}
	return nil
}

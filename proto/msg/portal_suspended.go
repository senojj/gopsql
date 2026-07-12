package msg

import "gopsql/internal/bytex"

const KindPortalSuspended byte = 's'

var _ Message = &PortalSuspended{}
var _ Backend = &PortalSuspended{}

type PortalSuspended struct{}

func (x *PortalSuspended) message() {}

func (x *PortalSuspended) backend() {}

func (x *PortalSuspended) AppendBinary(b []byte) ([]byte, error) {
	const length = sizeMessageLength
	const size = sizeMessageKind + length

	buf := bytex.NewBuffer(b)

	buf.Grow(size)
	buf.AppendByte(KindPortalSuspended)
	buf.AppendInt32(int32(length))
	return buf.Bytes(), nil
}

func (x *PortalSuspended) UnmarshalBinary(b []byte) error {
	kind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if kind != KindPortalSuspended {
		return unexpectedKind(kind, KindPortalSuspended)
	}

	if len(b) > 0 {
		return invalidFormat(bytex.ErrValueOverflow)
	}
	return nil
}

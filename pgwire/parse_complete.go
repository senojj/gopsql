package pgwire

import "gopsql/pgio"

const KindParseComplete byte = '1'

var _ Message = &ParseComplete{}
var _ Backend = &ParseComplete{}

type ParseComplete struct{}

func (x *ParseComplete) message() {}

func (x *ParseComplete) backend() {}

func (x *ParseComplete) AppendBinary(b []byte) ([]byte, error) {
	const length = sizeMessageLength
	const size = sizeMessageKind + length

	buf := pgio.NewBuffer(b)

	buf.Grow(size)
	buf.AppendByte(KindParseComplete)
	buf.AppendInt32(int32(length))
	return buf.Bytes(), nil
}

func (x *ParseComplete) UnmarshalBinary(b []byte) error {
	kind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if kind != KindParseComplete {
		return unexpectedKind(kind, KindParseComplete)
	}

	if len(b) > 0 {
		return invalidFormat(pgio.ErrValueOverflow)
	}
	return nil
}

package pgwire

import (
	"gopsql/pgio"
	"math"
)

const KindNegotiateProtocolVersion byte = 'v'

var _ Message = &NegotiateProtocolVersion{}
var _ Backend = &NegotiateProtocolVersion{}

type NegotiateProtocolVersion struct {
	MinorVersionSupported int32
	UnrecognizedOptions   []string
}

func (x *NegotiateProtocolVersion) message() {}

func (x *NegotiateProtocolVersion) backend() {}

func (x *NegotiateProtocolVersion) AppendBinary(b []byte) ([]byte, error) {
	const sizeMinorVersion = 4
	const sizeUnrecognizedOptionCount = 4

	length := sizeMessageLength +
		sizeMinorVersion +
		sizeUnrecognizedOptionCount

	countUnrecognizedOptions := len(x.UnrecognizedOptions)

	if countUnrecognizedOptions > math.MaxInt32 {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	for _, option := range x.UnrecognizedOptions {
		length += len(option)
	}

	if length > math.MaxInt32 {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(KindNegotiateProtocolVersion)
	buf.AppendInt32(int32(length))
	buf.AppendInt32(x.MinorVersionSupported)
	buf.AppendInt32(int32(countUnrecognizedOptions))
	buf.AppendString(x.UnrecognizedOptions...)
	return buf.Bytes(), nil
}

func (x *NegotiateProtocolVersion) UnmarshalBinary(b []byte) error {
	kind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if kind != KindNegotiateProtocolVersion {
		return unexpectedKind(kind, KindNegotiateProtocolVersion)
	}

	buf := pgio.NewBuffer(b)

	minorVersion, err := buf.ShiftInt32()
	if err != nil {
		return invalidFormat(err)
	}

	countUnsupportedOptions, err := buf.ShiftInt32()
	if err != nil {
		return invalidFormat(err)
	}

	options := make([]string, 0, countUnsupportedOptions)

	for range countUnsupportedOptions {
		option, err := buf.ShiftString()
		if err != nil {
			return invalidFormat(err)
		}
		options = append(options, option)
	}
	x.MinorVersionSupported = minorVersion
	x.UnrecognizedOptions = options
	return nil
}

package msg

import (
	"gopsql/internal/bytex"
	"math"
	"slices"
)

const KindNegotiateProtocolVersion byte = 'v'

var _ Message = &NegotiateProtocolVersion{}
var _ Backend = &NegotiateProtocolVersion{}

type NegotiateProtocolVersion struct {
	msg
	back

	MinorVersionSupported int32
	UnrecognizedOptions   []string
}

func (x *NegotiateProtocolVersion) AppendBinary(b []byte) ([]byte, error) {
	const sizeMinorVersion = 4
	const sizeUnrecognizedOptionCount = 4

	length := sizeMessageLength +
		sizeMinorVersion +
		sizeUnrecognizedOptionCount

	countUnrecognizedOptions := len(x.UnrecognizedOptions)

	if countUnrecognizedOptions > math.MaxInt32 {
		return nil, invalidFormat(bytex.ErrValueOverflow)
	}

	for _, option := range x.UnrecognizedOptions {
		length += len(option)
	}

	if length > math.MaxInt32 {
		return nil, invalidFormat(bytex.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	b = slices.Grow(b, size)
	b = bytex.AppendByte(b, KindNegotiateProtocolVersion)
	b = bytex.AppendInt32(b, int32(length))
	b = bytex.AppendInt32(b, x.MinorVersionSupported)
	b = bytex.AppendInt32(b, int32(countUnrecognizedOptions))
	b = bytex.AppendString(b, x.UnrecognizedOptions...)
	return b, nil
}

func (x *NegotiateProtocolVersion) UnmarshalBinary(b []byte) error {
	kind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if kind != KindNegotiateProtocolVersion {
		return unexpectedKind(kind, KindNegotiateProtocolVersion)
	}

	minorVersion, b, err := bytex.ShiftInt32(b)
	if err != nil {
		return invalidFormat(err)
	}

	countUnsupportedOptions, b, err := bytex.ShiftInt32(b)
	if err != nil {
		return invalidFormat(err)
	}

	options := make([]string, 0, countUnsupportedOptions)

	for range countUnsupportedOptions {
		var option string
		option, b, err = bytex.ShiftString(b)
		if err != nil {
			return invalidFormat(err)
		}
		options = append(options, option)
	}
	x.MinorVersionSupported = minorVersion
	x.UnrecognizedOptions = options
	return nil
}

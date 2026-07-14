package msg

import (
	"gopsql/internal/bytex"
	"math"
)

const (
	major3             int32 = 3
	minor2             int32 = 2
	ProtocolVersion3_2 int32 = minor2 | major3<<16
)

const (
	ParamUser        string = "user"
	ParamDatabase    string = "database"
	ParamOptions     string = "options"
	ParamReplication string = "replication"
)

type ProtocolVersion int32

func (x ProtocolVersion) Major() int32 {
	return int32(x) >> 16
}

func (x ProtocolVersion) Minor() int32 {
	return int32(x) & 0xFF
}

var _ Message = &StartupMessage{}
var _ Frontend = &StartupMessage{}

type StartupMessage struct {
	ProtocolVersion ProtocolVersion
	Parameters      map[string]string
}

func (x *StartupMessage) message() {}

func (x *StartupMessage) frontend() {}

func (x *StartupMessage) AppendBinary(b []byte) ([]byte, error) {
	const sizeProtocolVersion = 4

	var sizeParameters int

	for key, value := range x.Parameters {
		sizeParameters += (len(key) + 1)   // null terminated string
		sizeParameters += (len(value) + 1) // null terminated string
	}
	sizeParameters += 1 // null terminated list

	length := sizeMessageLength +
		sizeProtocolVersion +
		sizeParameters

	if length > math.MaxInt32 {
		return b, invalidFormat(bytex.ErrValueOverflow)
	}

	buf := bytex.NewBuffer(b)

	buf.Grow(length)
	buf.AppendInt32(int32(length))
	buf.AppendInt32(int32(x.ProtocolVersion))

	for key, value := range x.Parameters {
		buf.AppendString(key)
		buf.AppendString(value)
	}
	buf.AppendByte(0)
	return buf.Bytes(), nil
}

func (x *StartupMessage) UnmarshalBinary(b []byte) error {
	b, err := ShiftLength(b)
	if err != nil {
		return invalidFormat(err)
	}

	buf := bytex.NewBuffer(b)

	protocolVersion, err := buf.ShiftInt32()
	if err != nil {
		return invalidFormat(err)
	}

	parameters := make(map[string]string)

	key, err := buf.ShiftString()
	if err != nil {
		return invalidFormat(err)
	}

	for len(key) > 0 {
		value, err := buf.ShiftString()
		if err != nil {
			return invalidFormat(err)
		}
		parameters[key] = value

		key, err = buf.ShiftString()
		if err != nil {
			return invalidFormat(err)
		}
	}

	x.ProtocolVersion = ProtocolVersion(protocolVersion)
	x.Parameters = parameters
	return nil
}

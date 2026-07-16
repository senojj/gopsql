package pgwire

import "gopsql/pgio"

const (
	sslHigh        int32 = 1234
	sslLow         int32 = 5679
	CodeSSLRequest int32 = sslLow | sslHigh<<16
)

var _ Message = &SSLRequest{}
var _ Frontend = &SSLRequest{}

type SSLRequest struct{}

func (x *SSLRequest) message() {}

func (x *SSLRequest) frontend() {}

func (x *SSLRequest) AppendBinary(b []byte) ([]byte, error) {
	const sizeCode = 4

	length := sizeMessageLength + sizeCode

	buf := pgio.NewBuffer(b)

	buf.Grow(length)
	buf.AppendInt32(int32(length))
	buf.AppendInt32(CodeSSLRequest)
	return buf.Bytes(), nil
}

func (x *SSLRequest) UnmarshalBinary(b []byte) error {
	b, err := ShiftLength(b)
	if err != nil {
		return invalidFormat(err)
	}

	code, b, err := pgio.ShiftInt32(b)
	if err != nil {
		return invalidFormat(err)
	}

	if code != CodeSSLRequest {
		return invalidFormat(pgio.ErrUnknownCode)
	}

	if len(b) > 0 {
		return invalidFormat(pgio.ErrValueOverflow)
	}
	return nil
}

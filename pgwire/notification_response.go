package pgwire

import (
	"gopsql/pgio"
	"math"
)

var _ Message = &NotificationResponse{}
var _ Backend = &NotificationResponse{}

type NotificationResponse struct {
	ProcessID int32
	Channel   string
	Payload   string
}

func (x *NotificationResponse) message() {}

func (x *NotificationResponse) backend() {}

func (x *NotificationResponse) AppendBinary(b []byte) ([]byte, error) {
	const sizeProcessID = 4

	sizeChannel := len(x.Channel) + 1 // null terminated string
	sizePayload := len(x.Payload) + 1 // null terminated string

	length := sizeMessageLength +
		sizeProcessID +
		sizeChannel +
		sizePayload

	if length > math.MaxInt32 {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(byte(MsgNotificationResponse))
	buf.AppendInt32(int32(length))
	buf.AppendString(x.Channel)
	buf.AppendString(x.Payload)
	return buf.Bytes(), nil
}

func (x *NotificationResponse) UnmarshalBinary(b []byte) error {
	b, err := ShiftHeader(MsgNotificationResponse, b)
	if err != nil {
		return invalidFormat(err)
	}

	buf := pgio.NewBuffer(b)

	processID, err := buf.ShiftInt32()
	if err != nil {
		return invalidFormat(err)
	}

	channel, err := buf.ShiftString()
	if err != nil {
		return invalidFormat(err)
	}

	payload, err := buf.ShiftString()
	if err != nil {
		return invalidFormat(err)
	}

	x.ProcessID = processID
	x.Channel = channel
	x.Payload = payload
	return nil
}

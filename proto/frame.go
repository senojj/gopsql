package proto

import (
	"encoding/binary"
	"io"
)

type Header struct {
	Kind   byte
	Length int32
}

type Frame struct {
	Header Header
	Data   []byte
}

func NewFrame(kind byte, data []byte) Frame {
	return Frame{
		Header: Header{
			Kind:   kind,
			Length: int32(len(data) + 4),
		},
		Data: data,
	}
}

func NextFrame(r io.Reader) (Frame, error) {
	var h Header
	err := binary.Read(r, binary.BigEndian, &h)
	if err != nil {
		return Frame{}, err
	}
	b := make([]byte, h.Length-4)
	err = binary.Read(r, binary.BigEndian, b)
	if err != nil {
		return Frame{}, err
	}
	return Frame{h, b}, nil
}

func WriteFrame(w io.Writer, m Frame) error {
	err := binary.Write(w, binary.BigEndian, m.Header)
	if err != nil {
		return err
	}
	return binary.Write(w, binary.BigEndian, m.Data)
}

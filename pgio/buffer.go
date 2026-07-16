package pgio

import (
	"bytes"
	"slices"
)

type Buffer struct {
	data []byte
}

func NewBuffer(b []byte) *Buffer {
	return &Buffer{
		data: b,
	}
}

func (buf *Buffer) Bytes() []byte {
	return buf.data
}

func (buf *Buffer) Len() int {
	return len(buf.data)
}

func (buf *Buffer) Cap() int {
	return cap(buf.data)
}

func (buf *Buffer) Count(b []byte) int {
	return bytes.Count(buf.data, b)
}

func (buf *Buffer) Grow(n int) {
	buf.data = slices.Grow(buf.data, n)
}

func (buf *Buffer) ShiftByte() (value byte, err error) {
	value, buf.data, err = ShiftByte(buf.data)
	return
}

func (buf *Buffer) ShiftBytes(length int) (value []byte, err error) {
	value, buf.data, err = ShiftBytes(buf.data, length)
	return
}

func (buf *Buffer) ShiftInt8() (value int8, err error) {
	value, buf.data, err = ShiftInt8(buf.data)
	return
}

func (buf *Buffer) ShiftInt16() (value int16, err error) {
	value, buf.data, err = ShiftInt16(buf.data)
	return
}

func (buf *Buffer) ShiftInt32() (value int32, err error) {
	value, buf.data, err = ShiftInt32(buf.data)
	return
}

func (buf *Buffer) ShiftString() (value string, err error) {
	value, buf.data, err = ShiftString(buf.data)
	return
}

func (buf *Buffer) AppendByte(i ...byte) {
	buf.data = AppendByte(buf.data, i...)
}

func (buf *Buffer) AppendInt8(i ...int8) {
	buf.data = AppendInt8(buf.data, i...)
}

func (buf *Buffer) AppendInt16(i ...int16) {
	buf.data = AppendInt16(buf.data, i...)
}

func (buf *Buffer) AppendInt32(i ...int32) {
	buf.data = AppendInt32(buf.data, i...)
}

func (buf *Buffer) AppendInt64(i ...int64) {
	buf.data = AppendInt64(buf.data, i...)
}

func (buf *Buffer) AppendString(s ...string) {
	buf.data = AppendString(buf.data, s...)
}

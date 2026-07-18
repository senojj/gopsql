package pgwire

import "encoding"

type Message interface {
	encoding.BinaryAppender
	encoding.BinaryUnmarshaler

	message()
}

type Backend interface {
	Message

	backend()
}

type Frontend interface {
	Message

	frontend()
}

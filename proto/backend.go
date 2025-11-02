package proto

import "io"

type Backend struct {
	conn io.ReadWriter
	init bool
}

func (b *Backend) readFirst() (any, error) {
	var header [4]byte

	_, err := io.ReadFull(b.conn, header[:])
	if err != nil {
		if err == io.EOF {
			return nil, io.ErrUnexpectedEOF
		}
		return nil, err
	}

	var length int32
	_, err = readInt32(header[:], &length)
	if err != nil {
		return nil, err
	}

	data := make([]byte, length-4)
	_, err = io.ReadFull(b.conn, data)
	if err != nil {
		if err == io.EOF {
			return nil, io.ErrUnexpectedEOF
		}
		return nil, err
	}

	var code int32
	bread, err := readInt32(data, &code)
	if err != nil {
		return nil, err
	}
	data = data[bread:]

	switch code {
	case codeCancelRequest:
		var req MsgCancelRequest
		err = req.Decode(data)
		if err != nil {
			return nil, err
		}
		return &req, nil
	default:
		return nil, ErrUnknownCode
	}
}

func (b *Backend) Read() (any, error) {
	var header [5]byte

	if !b.init {
		msg, err := b.readFirst()
		if err != nil {
			return nil, err
		}
		b.init = true
		return msg, nil
	}
	_, err := io.ReadFull(b.conn, header[:])
	if err != nil {
		if err == io.EOF {
			return nil, io.ErrUnexpectedEOF
		}
		return nil, err
	}

	kind := header[0]

	var length int32
	_, err = readInt32(header[1:], &length)
	if err != nil {
		return nil, err
	}

	data := make([]byte, length-4)
	_, err = io.ReadFull(b.conn, data)
	if err != nil {
		if err == io.EOF {
			return nil, io.ErrUnexpectedEOF
		}
		return nil, err
	}

	return b.parseMessage(kind, data)
}

func (b *Backend) parseMessage(kind byte, data []byte) (any, error) {
	var dec Decoder

	switch kind {
	case msgKindAuthentication:
		var k int32
		bread, err := readInt32(data, &k)
		if err != nil {
			return nil, err
		}
		d := data[bread:]
		return b.parseAuthentication(k, d)
	case msgKindBackendKeyData:
		dec = new(MsgBackendKeyData)
	case msgKindBind:
		dec = new(MsgBind)
	case msgKindBindComplete:
		dec = new(MsgBindComplete)
	case msgKindCloseComplete:
		dec = new(MsgCloseComplete)
	case msgKindCommandComplete:
		dec = new(MsgCommandComplete)
	case msgKindCopyData:
		dec = new(MsgCopyData)
	case msgKindCopyDone:
		dec = new(MsgCopyDone)
	case msgKindCopyInResponse:
		dec = new(MsgCopyInResponse)
	case msgKindCopyOutResponse:
		dec = new(MsgCopyOutResponse)
	case msgKindCopyBothResponse:
		dec = new(MsgCopyBothResponse)
	case msgKindDataRow:
		dec = new(MsgDataRow)
	case msgKindEmptyQueryResponse:
		dec = new(MsgEmptyQueryResponse)
	case msgKindErrorResponse:
		dec = new(MsgErrorResponse)
	case msgKindFunctionCallResponse:
		dec = new(MsgFunctionCallResponse)
	case msgKindNegotiateProtocolVersion:
		dec = new(MsgNegotiateProtocolVersion)
	case msgKindNoData:
		dec = new(MsgNoData)
	case msgKindNoticeResponse:
		dec = new(MsgNoticeResponse)
	case msgKindNotificationResponse:
		dec = new(MsgNotificationResponse)
	case msgKindParameterDescription:
		dec = new(MsgParameterDescription)
	case msgKindParameterStatus:
		dec = new(MsgParameterStatus)
	case msgKindParseComplete:
		dec = new(MsgParseComplete)
	case msgKindPortalSuspended:
		dec = new(MsgPortalSuspended)
	case msgKindReadyForQuery:
		dec = new(MsgReadyForQuery)
	case msgKindRowDescription:
		dec = new(MsgRowDescription)
	default:
		dec = new(MsgUnknown)
	}
	err := dec.Decode(data)
	if err != nil {
		return nil, err
	}
	return dec, nil
}

func (b *Backend) parseAuthentication(kind int32, data []byte) (any, error) {
	var dec Decoder

	switch kind {
	case authKindOk:
		dec = new(MsgAuthOk)
	case authKindKerberosV5:
		dec = new(MsgAuthKerberosV5)
	case authKindCleartextPassword:
		dec = new(MsgAuthCleartextPassword)
	case authKindMD5Password:
		dec = new(MsgAuthMD5Password)
	case authKindGSS:
		dec = new(MsgAuthGSS)
	case authKindGSSContinue:
		dec = new(MsgAuthGSSContinue)
	case authKindSSPI:
		dec = new(MsgAuthSSPI)
	case authKindSASL:
		dec = new(MsgAuthSASL)
	case authKindSASLContinue:
		dec = new(MsgAuthSASLContinue)
	case authKindSASLFinal:
		dec = new(MsgAuthSASLFinal)
	default:
		dec = new(MsgUnknownAuth)
	}
	err := dec.Decode(data)
	if err != nil {
		return nil, err
	}
	return dec, nil
}

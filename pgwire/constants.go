package pgwire

type MessageKind byte

func (x MessageKind) Is(b byte) bool {
	return x == MessageKind(b)
}

// Backend messages
const (
	MsgAuthentication           MessageKind = 'R'
	MsgBackendKeyData           MessageKind = 'K'
	MsgBindComplete             MessageKind = '2'
	MsgCloseComplete            MessageKind = '3'
	MsgCommandComplete          MessageKind = 'C'
	MsgCopyInResponse           MessageKind = 'G'
	MsgCopyOutResponse          MessageKind = 'H'
	MsgCopyBothResponse         MessageKind = 'W'
	MsgDataRow                  MessageKind = 'D'
	MsgEmptyQueryResponse       MessageKind = 'I'
	MsgErrorResponse            MessageKind = 'E'
	MsgFunctionCallResponse     MessageKind = 'V'
	MsgNegotiateProtocolVersion MessageKind = 'v'
	MsgNoData                   MessageKind = 'n'
	MsgNoticeResponse           MessageKind = 'N'
	MsgNotificationResponse     MessageKind = 'A'
	MsgParameterDescription     MessageKind = 't'
	MsgParameterStatus          MessageKind = 'S'
	MsgParseComplete            MessageKind = '1'
	MsgPortalSuspend            MessageKind = 's'
	MsgReadyForQuery            MessageKind = 'Z'
	MsgRowDescription           MessageKind = 'T'
)

// Frontend messages
const (
	MsgBind                MessageKind = 'B'
	MsgClose               MessageKind = 'C'
	MsgCopyFail            MessageKind = 'f'
	MsgDescribe            MessageKind = 'D'
	MsgExecute             MessageKind = 'E'
	MsgFlush               MessageKind = 'H'
	MsgFunctionCall        MessageKind = 'F'
	MsgGSSResponse         MessageKind = 'p'
	MsgParse               MessageKind = 'P'
	MsgPasswordMessage     MessageKind = 'p'
	MsgQuery               MessageKind = 'Q'
	MsgSASLInitialResponse MessageKind = 'p'
	MsgSASLResponse        MessageKind = 'p'
	MsgSync                MessageKind = 'S'
	MsgTerminate           MessageKind = 'X'
)

// Backend + Frontend messages
const (
	MsgCopyData MessageKind = 'd'
	MsgCopyDone MessageKind = 'c'
)

type AuthenticationKind int32

func (x AuthenticationKind) Is(i int32) bool {
	return x == AuthenticationKind(i)
}

const (
	AuthOk                AuthenticationKind = 0
	AuthKerberosV5        AuthenticationKind = 2
	AuthClearTextPassword AuthenticationKind = 3
	AuthMD5Password       AuthenticationKind = 5
	AuthGSS               AuthenticationKind = 7
	AuthGSSContinue       AuthenticationKind = 8
	AuthSSPI              AuthenticationKind = 9
	AuthSASL              AuthenticationKind = 10
	AuthSASLContinue      AuthenticationKind = 11
	AuthSASLFinal         AuthenticationKind = 12
)

type FieldKind byte

const (
	FldSeverity         FieldKind = 'S'
	FldSeverityRaw      FieldKind = 'V'
	FldCode             FieldKind = 'C'
	FldMessage          FieldKind = 'M'
	FldDetail           FieldKind = 'D'
	FldHint             FieldKind = 'H'
	FldPosition         FieldKind = 'P'
	FldInternalPosition FieldKind = 'p'
	FldInternalQuery    FieldKind = 'q'
	FldWhere            FieldKind = 'W'
	FldSchema           FieldKind = 's'
	FldTable            FieldKind = 't'
	FldColumn           FieldKind = 'c'
	FldDataType         FieldKind = 'd'
	FldConstraint       FieldKind = 'n'
	FldFile             FieldKind = 'F'
	FldLine             FieldKind = 'L'
	FldRoutine          FieldKind = 'R'
)

type ObjectKind byte

const (
	ObjStatement ObjectKind = 'S'
	ObjPortal    ObjectKind = 'P'
)

type FormatKind byte

const (
	FmtText   FormatKind = 0
	FmtBinary FormatKind = 1
)

type TransactionStatusKind byte

const (
	TxIdle   TransactionStatusKind = 'I'
	TxActive TransactionStatusKind = 'T'
	TxError  TransactionStatusKind = 'E'
)

const (
	sizeMessageKind   = 1
	sizeMessageLength = 4
	sizeAuthKind      = 4
)

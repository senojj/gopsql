package pgwire

const (
	cancelHigh        int32 = 1234
	cancelLow         int32 = 5678
	CodeCancelRequest int32 = cancelLow | cancelHigh<<16
)

const (
	sslHigh        int32 = 1234
	sslLow         int32 = 5679
	CodeSSLRequest int32 = sslLow | sslHigh<<16
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

type MessageKind byte

func (x MessageKind) Is(b byte) bool {
	return x == MessageKind(b)
}

// Backend messages
const (
	MessageKindAuthentication           MessageKind = 'R'
	MessageKindBackendKeyData           MessageKind = 'K'
	MessageKindBindComplete             MessageKind = '2'
	MessageKindCloseComplete            MessageKind = '3'
	MessageKindCommandComplete          MessageKind = 'C'
	MessageKindCopyInResponse           MessageKind = 'G'
	MessageKindCopyOutResponse          MessageKind = 'H'
	MessageKindCopyBothResponse         MessageKind = 'W'
	MessageKindDataRow                  MessageKind = 'D'
	MessageKindEmptyQueryResponse       MessageKind = 'I'
	MessageKindErrorResponse            MessageKind = 'E'
	MessageKindFunctionCallResponse     MessageKind = 'V'
	MessageKindNegotiateProtocolVersion MessageKind = 'v'
	MessageKindNoData                   MessageKind = 'n'
	MessageKindNoticeResponse           MessageKind = 'N'
	MessageKindNotificationResponse     MessageKind = 'A'
	MessageKindParameterDescription     MessageKind = 't'
	MessageKindParameterStatus          MessageKind = 'S'
	MessageKindParseComplete            MessageKind = '1'
	MessageKindPortalSuspend            MessageKind = 's'
	MessageKindReadyForQuery            MessageKind = 'Z'
	MessageKindRowDescription           MessageKind = 'T'
)

// Frontend messages
const (
	MessageKindBind                MessageKind = 'B'
	MessageKindClose               MessageKind = 'C'
	MessageKindCopyFail            MessageKind = 'f'
	MessageKindDescribe            MessageKind = 'D'
	MessageKindExecute             MessageKind = 'E'
	MessageKindFlush               MessageKind = 'H'
	MessageKindFunctionCall        MessageKind = 'F'
	MessageKindGSSResponse         MessageKind = 'p'
	MessageKindParse               MessageKind = 'P'
	MessageKindPasswordMessage     MessageKind = 'p'
	MessageKindQuery               MessageKind = 'Q'
	MessageKindSASLInitialResponse MessageKind = 'p'
	MessageKindSASLResponse        MessageKind = 'p'
	MessageKindSync                MessageKind = 'S'
	MessageKindTerminate           MessageKind = 'X'
)

// Backend + Frontend messages
const (
	MessageKindCopyData MessageKind = 'd'
	MessageKindCopyDone MessageKind = 'c'
)

type AuthenticationKind int32

func (x AuthenticationKind) Is(i int32) bool {
	return x == AuthenticationKind(i)
}

const (
	AuthenticationKindOk                AuthenticationKind = 0
	AuthenticationKindKerberosV5        AuthenticationKind = 2
	AuthenticationKindClearTextPassword AuthenticationKind = 3
	AuthenticationKindMD5Password       AuthenticationKind = 5
	AuthenticationKindGSS               AuthenticationKind = 7
	AuthenticationKindGSSContinue       AuthenticationKind = 8
	AuthenticationKindSSPI              AuthenticationKind = 9
	AuthenticationKindSASL              AuthenticationKind = 10
	AuthenticationKindSASLContinue      AuthenticationKind = 11
	AuthenticationKindSASLFinal         AuthenticationKind = 12
)

type FieldKind byte

const (
	FieldKindSeverity         FieldKind = 'S'
	FieldKindSeverityRaw      FieldKind = 'V'
	FieldKindCode             FieldKind = 'C'
	FieldKindMessage          FieldKind = 'M'
	FieldKindDetail           FieldKind = 'D'
	FieldKindHint             FieldKind = 'H'
	FieldKindPosition         FieldKind = 'P'
	FieldKindInternalPosition FieldKind = 'p'
	FieldKindInternalQuery    FieldKind = 'q'
	FieldKindWhere            FieldKind = 'W'
	FieldKindSchema           FieldKind = 's'
	FieldKindTable            FieldKind = 't'
	FieldKindColumn           FieldKind = 'c'
	FieldKindDataType         FieldKind = 'd'
	FieldKindConstraint       FieldKind = 'n'
	FieldKindFile             FieldKind = 'F'
	FieldKindLine             FieldKind = 'L'
	FieldKindRoutine          FieldKind = 'R'
)

type ObjectKind byte

const (
	ObjectKindStatement ObjectKind = 'S'
	ObjectKindPortal    ObjectKind = 'P'
)

type FormatKind byte

const (
	FormatKindText   FormatKind = 0
	FormatKindBinary FormatKind = 1
)

type TransactionStatusKind byte

const (
	TransactionStatusKindIdle   TransactionStatusKind = 'I'
	TransactionStatusKindActive TransactionStatusKind = 'T'
	TransactionStatusKindError  TransactionStatusKind = 'E'
)

const (
	sizeMessageKind   = 1
	sizeMessageLength = 4
	sizeAuthKind      = 4
)

package i18n

// LoginExpectMessages holds the texts of a host's Expect/Send rules: the section
// in the host dialog, the one-rule editor, and the prompt for a sensitive
// response.
type LoginExpectMessages struct {
	SectionTitle string
	SectionHint  string
	Enabled      string
	Empty        string
	StepFmt      string

	WaitLabel            string
	WaitPlaceholder      string
	SendLabel            string
	SendPlaceholder      string
	SensitivePlaceholder string
	TimeoutLabel         string
	DelayLabel           string
	DelayPlaceholder     string
	AppendEnter          string
	Sensitive            string

	Add      string
	Edit     string
	Delete   string
	MoveUp   string
	MoveDown string
	Save     string

	StepTitleAdd    string
	StepTitleEdit   string
	StepSummaryFmt  string
	DelaySummaryFmt string
	AskedSummary    string
	EnterSummary    string

	DialogTitle string
	DialogHint  string
	ResponseFmt string

	Timeout     string
	WriteFailed string
	Cancelled   string
	FailedFmt   string

	ErrTimeout string
	ErrDelay   string
	ErrEmpty   string
}

var englishLoginExpect = LoginExpectMessages{
	SectionTitle: "Login script",
	SectionHint:  "Wait for text the shell prints, then send a reply. Rules run in order once the shell opens; a timeout stops the rest and leaves the terminal to you.",
	Enabled:      "Run these rules when the shell opens",
	Empty:        "No rules yet.",
	StepFmt:      "Step %d",

	WaitLabel:            "Wait for",
	WaitPlaceholder:      "Text to wait for (\\r, \\n, \\xNN allowed)",
	SendLabel:            "Send",
	SendPlaceholder:      "Reply to send",
	SensitivePlaceholder: "Asked at runtime",
	TimeoutLabel:         "Timeout (seconds)",
	DelayLabel:           "Delay before reply (ms)",
	DelayPlaceholder:     "0",
	AppendEnter:          "Press Enter after the reply",
	Sensitive:            "Ask for the reply at runtime (never saved)",

	Add:      "Add rule",
	Edit:     "Edit",
	Delete:   "Delete",
	MoveUp:   "Move up",
	MoveDown: "Move down",
	Save:     "Save",

	StepTitleAdd:    "Add login rule",
	StepTitleEdit:   "Edit login rule",
	StepSummaryFmt:  "wait %s → %s · %ds",
	DelaySummaryFmt: " · +%dms",
	AskedSummary:    "asked at runtime",
	EnterSummary:    " ⏎",

	DialogTitle: "Login response required",
	DialogHint:  "This rule asks for its reply. It is sent once and never saved or logged.",
	ResponseFmt: "Login response %d",

	Timeout:     "Login script stopped: a prompt did not appear in time. The terminal is yours.",
	WriteFailed: "Login script stopped: the shell refused a reply. The terminal is yours.",
	Cancelled:   "Login script cancelled; continue manually.",
	FailedFmt:   "Login script stopped: %v",

	ErrTimeout: "The timeout must be a whole number of seconds.",
	ErrDelay:   "The delay must be a whole number of milliseconds, 0 or more.",
	ErrEmpty:   "A rule needs something to wait for, a reply, or a runtime reply.",
}

var chineseLoginExpect = LoginExpectMessages{
	SectionTitle: "登录脚本",
	SectionHint:  "等待终端输出指定文本后自动回复。连接 shell 后按顺序执行；超时会停止后续规则并把终端交还给用户。",
	Enabled:      "shell 打开时运行这些规则",
	Empty:        "还没有规则。",
	StepFmt:      "第 %d 步",

	WaitLabel:            "等待文本",
	WaitPlaceholder:      "要等待的文本（可用 \\r、\\n、\\xNN）",
	SendLabel:            "回复",
	SendPlaceholder:      "要发送的回复",
	SensitivePlaceholder: "运行时询问",
	TimeoutLabel:         "超时（秒）",
	DelayLabel:           "回复延迟（毫秒）",
	DelayPlaceholder:     "0",
	AppendEnter:          "回复后按回车",
	Sensitive:            "运行时询问回复（不保存）",

	Add:      "添加规则",
	Edit:     "编辑",
	Delete:   "删除",
	MoveUp:   "上移",
	MoveDown: "下移",
	Save:     "保存",

	StepTitleAdd:    "添加登录规则",
	StepTitleEdit:   "编辑登录规则",
	StepSummaryFmt:  "等待 %s → %s · %d 秒",
	DelaySummaryFmt: " · +%d 毫秒",
	AskedSummary:    "运行时询问",
	EnterSummary:    " ⏎",

	DialogTitle: "需要登录回复",
	DialogHint:  "该规则需要在运行时输入回复。回复只发送一次，不会保存或记录。",
	ResponseFmt: "登录回复 %d",

	Timeout:     "登录脚本已停止：等待的提示未在超时内出现。终端已交还给你。",
	WriteFailed: "登录脚本已停止：shell 拒绝了回复。终端已交还给你。",
	Cancelled:   "登录脚本已取消，请手动继续。",
	FailedFmt:   "登录脚本已停止：%v",

	ErrTimeout: "超时必须是整数秒。",
	ErrDelay:   "延迟必须是大于等于 0 的整数毫秒。",
	ErrEmpty:   "规则需要等待文本、回复或运行时回复中的至少一项。",
}

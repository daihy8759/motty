package i18n

// CompletionMessages are the texts of command completion: the assembled list,
// its Settings group and the catalog's status.
type CompletionMessages struct {
	Title                 string
	Open                  string
	ModeOff               string
	ModeList              string
	ModeBoth              string
	KeysGroup             string
	KeysAccept            string
	KeysAcceptWord        string
	KeysSelect            string
	KeysInsert            string
	KeysInsertDescription string
	KeysClose             string
	KeysShell             string
	KeysShellDescription  string
	Group                 string
	CatalogRow            string
	CatalogDescriptionFmt string
	CatalogLoading        string
	CatalogOff            string
	Check                 string
	Updating              string
	UpToDate              string
	UpdatedFmt            string
	CheckFailedFmt        string
	CacheFailedFmt        string
	CheckedFmt            string
	NoDataDir             string
}

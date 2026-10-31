package completion

// Bounds for anything that enters the catalog. They are deliberately generous
// for the real Carapace snapshot and small enough that a hostile archive or a
// corrupt cache cannot exhaust memory or make the UI stall.
const (
	// maxDepth is the deepest command nesting accepted from a source file.
	maxDepth = 32
	// maxDescRunes keeps a description short enough for a one-line list row.
	maxDescRunes = 160
	// maxValueBytes bounds one literal option value.
	maxValueBytes = 128
	// maxValuesPerFlag bounds the literal values imported for a single option.
	maxValuesPerFlag = 64
	// maxCatalogNodes bounds the whole catalog.
	maxCatalogNodes = 200_000

	// maxArchiveBytes bounds the compressed archive read during an update.
	maxArchiveBytes = 64 << 20
	// maxExpandedBytes bounds the total uncompressed bytes read.
	maxExpandedBytes = 128 << 20
	// maxArchiveMembers bounds the archive members visited.
	maxArchiveMembers = 20_000
	// maxSourceFileBytes bounds one YAML file.
	maxSourceFileBytes = 1 << 20
	// maxYAMLDepth bounds nesting inside one YAML document.
	maxYAMLDepth = 64
	// maxYAMLNodes bounds the nodes of one YAML document.
	maxYAMLNodes = 200_000
)

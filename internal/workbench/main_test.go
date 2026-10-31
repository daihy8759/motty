package workbench

import (
	"os"
	"testing"

	"github.com/vivaui/viva/leaks"

	"motty/internal/backup"
)

// The tests must close every shell and worker they start.
func TestMain(m *testing.M) {
	backup.UseCheapKDFForTests()
	os.Exit(leaks.Main(m))
}

//go:build !windows

package localshell

import (
	"slices"
	"testing"
)

func TestShellLocaleFillsOnlyAnEnvironmentThatNamesNoLocale(t *testing.T) {
	for _, test := range []struct {
		name string
		env  []string
		want []string
	}{
		{"nothing set", []string{"HOME=/tmp"}, []string{"HOME=/tmp", "LANG=C.UTF-8"}},
		{"empty settings", []string{"LANG=", "LC_CTYPE=", "HOME=/tmp"}, []string{"HOME=/tmp", "LANG=C.UTF-8"}},
		{"a locale", []string{"LANG=en_US.UTF-8"}, []string{"LANG=en_US.UTF-8"}},
		{"a character type", []string{"LC_CTYPE=zh_CN.UTF-8", "HOME=/tmp"}, []string{"LC_CTYPE=zh_CN.UTF-8", "HOME=/tmp"}},
		{"an explicit C locale", []string{"LC_ALL=C"}, []string{"LC_ALL=C"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := withUTF8Locale(slices.Clone(test.env)); !slices.Equal(got, test.want) {
				t.Fatalf("withUTF8Locale(%q) = %q, want %q", test.env, got, test.want)
			}
		})
	}
}

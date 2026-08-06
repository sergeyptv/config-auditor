package configutil

import (
	"reflect"
	"sort"
	"testing"
)

func TestWalk(t *testing.T) {
	cfg := map[string]any{
		"application": map[string]any{
			"log": map[string]any{
				"level": "debug",
			},
		},
		"servers": []any{
			map[string]any{
				"host": "127.0.0.1",
			},
		},
	}

	var paths []string

	Walk(cfg, func(entry Entry) {
		paths = append(paths, entry.Path)
	})

	expectedPaths := []string{
		"application",
		"application.log",
		"application.log.level",
		"servers",
		"servers[0]",
		"servers[0].host",
	}

	sort.Strings(paths)
	sort.Strings(expectedPaths)

	if !reflect.DeepEqual(paths, expectedPaths) {
		t.Fatalf("unexpected paths:\nexpected: %#v\nactual:	%#v", expectedPaths, paths)
	}
}

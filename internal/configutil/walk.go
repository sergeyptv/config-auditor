package configutil

import (
	"fmt"
)

type Entry struct {
	Path  string
	Key   string
	Value any
}

type Visitor func(entry Entry)

func Walk(value any, visitor Visitor) {
	walk(value, "", visitor)
}

func walk(value any, currentPath string, visitor Visitor) {
	switch node := value.(type) {
	case map[string]any:
		for key, child := range node {
			childPath := joinPath(currentPath, key)

			visitor(Entry{
				Path:  childPath,
				Key:   key,
				Value: child,
			})

			walk(child, childPath, visitor)
		}

	case []any:
		for idx, child := range node {
			childPath := fmt.Sprintf("%s[%d]", currentPath, idx)

			visitor(Entry{
				Path:  childPath,
				Value: child,
			})

			walk(child, childPath, visitor)
		}
	}
}

func joinPath(parent, child string) string {
	if parent == "" {
		return child
	}

	return parent + "." + child
}

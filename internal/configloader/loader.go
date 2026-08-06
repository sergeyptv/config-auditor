package configloader

import (
	"errors"
	"fmt"
	"github.com/sergeyptv/config-auditor/internal/parser"
	"io"
)

const MaxConfigSize int64 = 10 * 1024 * 1024

var ErrConfigTooLarge = errors.New("configuration is more than maximum allowed size")

func Load(reader io.Reader, format parser.Format) (map[string]any, error) {
	limitedReader := io.LimitReader(reader, MaxConfigSize+1)

	data, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("read configuration: %w", err)
	}

	if int64(len(data)) > MaxConfigSize {
		return nil, fmt.Errorf("%w: maximum size is %d bytes", ErrConfigTooLarge, MaxConfigSize)
	}

	cfg, err := parser.Parse(data, format)
	if err != nil {
		return nil, fmt.Errorf("parse configuration: %w", err)
	}

	return cfg, nil
}

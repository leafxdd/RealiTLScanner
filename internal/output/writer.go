package output

import (
	"fmt"
	"io"

	"github.com/xtls/RealiTLScanner/internal/types"
)

type Writer interface {
	WriteHeader() error
	WriteResult(result *types.ScanResult) error
	Flush() error
	Close() error
}

type Options struct {
	Extended bool
	Pretty   bool
	Progress bool
	NoHeader bool
}

var ValidFormats = []string{"csv", "json", "jsonl", "csv-extended"}

func NewWriter(format string, w io.Writer, opts Options) (Writer, error) {
	switch format {
	case "csv":
		return NewCSVWriter(w, opts), nil
	case "json":
		return NewJSONWriter(w, opts), nil
	case "jsonl":
		return NewJSONLWriter(w), nil
	case "csv-extended":
		opts.Extended = true
		return NewCSVWriter(w, opts), nil
	default:
		return nil, fmt.Errorf("unsupported output format: %q (valid: csv, json, jsonl, csv-extended)", format)
	}
}

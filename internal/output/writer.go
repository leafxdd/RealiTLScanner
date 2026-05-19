package output

import (
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

func NewWriter(format string, w io.Writer, opts Options) Writer {
	switch format {
	case "json":
		return NewJSONWriter(w, opts)
	case "jsonl":
		return NewJSONLWriter(w)
	case "csv-extended":
		opts.Extended = true
		return NewCSVWriter(w, opts)
	default:
		return NewCSVWriter(w, opts)
	}
}

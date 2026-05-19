package detector

import (
	"context"

	"github.com/xtls/RealiTLScanner/internal/types"
)

type Detector interface {
	Name() string
	Detect(ctx context.Context, result *types.ScanResult) error
	Available() bool
}

package normalise

import "github.com/nobledeveloper01/StatusHub/internal/adapter"

// Aliases so the metric-label mapping above does not have to import the
// adapter package under a name that reads like a provider.
var (
	errNoTransaction = adapter.ErrNoTransaction
	errUnparseable   = adapter.ErrUnparseable
)

package session

import "context"

type option func(m map[string]any)

type SessionProvider interface {
	NewSession(ctx context.Context, attr ...option) (Session, error)
	ParseSession(ctx context.Context, rawSession string, attr ...option) (Session, error)
}

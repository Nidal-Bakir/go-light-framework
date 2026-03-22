package session

import (
	"context"
	"time"
)

type StoreProvider interface {
	StoreAttr(ctx context.Context, session string, expiresAfter time.Duration, fields ...string) (err error)
	GetAttr(ctx context.Context, session, key string) (string, error)
	RemoveAttr(ctx context.Context, session, key string) error
}

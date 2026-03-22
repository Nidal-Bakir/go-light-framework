package session

import (
	"context"
	"time"
)

type Session interface {
	String() string
	StoreAttr(ctx context.Context, expiresAfter time.Duration, fields ...string) (err error)
	GetAttr(ctx context.Context, key string) (string, error)
	RemoveAttr(ctx context.Context, key string) error
}


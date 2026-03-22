package session

import (
	"context"
	"time"

	"github.com/Nidal-Bakir/go-todo-backend/internal/utils/appjwt"
)

func newJwtSession(rawSession string, claims appjwt.CustomClaims, store StoreProvider) Session {
	return &jwtSession{rawSession: rawSession, claims: claims, store: store}
}

type jwtSession struct {
	rawSession string
	store      StoreProvider
	claims     appjwt.CustomClaims
}

func (s jwtSession) String() string {
	return s.rawSession
}

func (s jwtSession) StoreAttr(ctx context.Context, expiresAfter time.Duration, fields ...string) (err error) {
	return s.store.StoreAttr(ctx, s.String(), expiresAfter, fields...)
}

func (s jwtSession) GetAttr(ctx context.Context, key string) (string, error) {
	c, ok := s.claims.Claims[key]
	if ok {
		return c, nil
	}
	return s.store.GetAttr(ctx, s.String(), key)

}

func (s jwtSession) RemoveAttr(ctx context.Context, key string) error {
	return s.store.RemoveAttr(ctx, s.String(), key)
}

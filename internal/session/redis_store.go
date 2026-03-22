package session

import (
	"context"
	"fmt"
	"time"

	redisdb "github.com/Nidal-Bakir/go-todo-backend/internal/redis_db"
	"github.com/Nidal-Bakir/go-todo-backend/internal/utils"
	"github.com/redis/go-redis/v9"
)

type redisStore struct {
	redis *redis.Client
}

func NewRedisStore(redis *redis.Client) StoreProvider {
	return &redisStore{redis}
}

func (r redisStore) StoreAttr(ctx context.Context, session string, expiresAfter time.Duration, fields ...string) error {
	l := len(fields)
	utils.Assert(l%2 == 0, "fields must be key-value pairs")
	if l == 0 {
		return nil
	}
	return r.redis.HSetEXWithArgs(
		ctx,
		r.genSessionKey(session),
		&redis.HSetEXOptions{
			ExpirationType: redis.HSetEXExpirationEX,
			ExpirationVal:  int64(expiresAfter.Seconds()),
		},
		fields...,
	).Err()
}

func (r redisStore) GetAttr(ctx context.Context, session, key string) (string, error) {
	val, err := r.redis.HGet(ctx, r.genSessionKey(session), key).Result()
	if err != nil {
		if redisdb.IsRedisNil(err) {
			return "", nil
		}
		return "", err
	}
	return val, nil
}

func (r redisStore) RemoveAttr(ctx context.Context, session, key string) error {
	err := r.redis.HDel(ctx, r.genSessionKey(session), key).Err()
	if redisdb.IsRedisNil(err) {
		return nil
	}
	return err
}

func (r redisStore) genSessionKey(session string) string {
	return fmt.Sprint("session:store:", session)
}

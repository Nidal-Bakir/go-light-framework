package redisdb

import (
	"errors"

	"github.com/redis/go-redis/v9"
)

func IsRedisNil(err error) bool {
	return errors.Is(err, redis.Nil)
}

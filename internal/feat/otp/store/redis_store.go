package otp

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/Nidal-Bakir/go-todo-backend/internal/utils"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

type redisStore struct {
	redis *redis.Client
}

func NewRedisStore(redis *redis.Client) StoreProvider {
	return &redisStore{redis}
}

func (s *redisStore) StoreOtp(ctx context.Context, otpHash string, channel otpChannel, ExpiresAfter time.Duration) (id string, err error) {
	id = uuid.New().String()
	err = s.redis.HSetEXWithArgs(
		ctx,
		s.generateKey(id),
		&redis.HSetEXOptions{
			ExpirationType: redis.HSetEXExpirationEX,
			ExpirationVal:  int64(ExpiresAfter.Seconds()),
		},
		OtpStoreModel{
			ID:        id,
			OtpHash:   otpHash,
			Channel:   channel,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			Attempts:  0,
			ExpiresAt: time.Now().Add(ExpiresAfter),
		}.toKeyValueSlice()...,
	).Err()
	return id, err
}

func (s *redisStore) GetOtp(ctx context.Context, id string) (*OtpStoreModel, error) {
	resultMap, err := s.redis.HGetAll(ctx, s.generateKey(id)).Result()
	if err != nil {
		return nil, err
	}
	return new(OtpStoreModel).fromMap(resultMap), nil
}

func (s *redisStore) RemoveOtp(ctx context.Context, id string) error {
	return s.redis.Del(ctx, s.generateKey(id)).Err()
}

var script = redis.NewScript(`
local attempts = redis.call("HGET", KEYS[1], ARGV[1])

if not attempts then
   attempts = 0
else
   attempts = tonumber(attempts)
end

local max = tonumber(ARGV[2])

if attempts < max then
   return redis.call("HINCRBY", KEYS[1], ARGV[1], ARGV[3])
else
   return attempts
end
`)

func (s *redisStore) IncrementAttemptCounter(ctx context.Context, id string, limit int) (int, error) {
	return script.Run(
		ctx,
		s.redis,
		[]string{s.generateKey(id)}, // KEYS
		"attempts",                  // ARGV[1]
		limit,                       // ARGV[2]
		1,                           // ARGV[3] increment
	).Int()
}

func (s *redisStore) generateKey(id string) string {
	return fmt.Sprint("otp:", id)
}

func (m OtpStoreModel) toKeyValueSlice() []string {
	return []string{
		"id", m.ID,
		"otp_hash", m.OtpHash,
		"channel", m.Channel.String(),
		"attempts", strconv.Itoa(m.Attempts),
		"created_at", m.CreatedAt.Format(time.RFC3339),
		"updated_at", m.UpdatedAt.Format(time.RFC3339),
		"expires_at", m.ExpiresAt.Format(time.RFC3339),
	}
}

func (m *OtpStoreModel) fromMap(data map[string]string) *OtpStoreModel {
	m.ID = data["id"]
	m.OtpHash = data["otp_hash"]
	m.Channel = otpChannel(data["channel"])
	m.Attempts = utils.Must(strconv.Atoi(data["attempts"]))
	m.CreatedAt = utils.Must(time.Parse(time.RFC3339, data["created_at"]))
	m.UpdatedAt = utils.Must(time.Parse(time.RFC3339, data["updated_at"]))
	m.ExpiresAt = utils.Must(time.Parse(time.RFC3339, data["expires_at"]))
	return m
}

package otp

import (
	"context"
	"fmt"
	"strconv"
	"time"

	redisdb "github.com/Nidal-Bakir/go-todo-backend/internal/redis_db"
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

func (s *redisStore) StoreOtp(ctx context.Context, otpHash string, purpose otpPurpose, channel otpChannel, ExpiresAfter time.Duration) (id string, err error) {
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
			Purpose:   purpose,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			Attempts:  1,
			ExpiresAt: time.Now().Add(ExpiresAfter),
		}.toKeyValueSlice()...,
	).Err()
	return id, err
}

func (s *redisStore) GetOtp(ctx context.Context, id string) (*OtpStoreModel, error) {
	resultMap, err := s.redis.HGetAll(ctx, s.generateKey(id)).Result()
	if err != nil {
		if redisdb.IsErrRedisNilNoRows(err) {
			return nil, NotFoundOTP
		}
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
    return {"ERROR", "FIELD_NOT_FOUND", KEYS[1], ARGV[1]}
end

attempts = tonumber(attempts)
local max = tonumber(ARGV[2])
local limit_reached = attempts >= max

if limit_reached
	return {"OK", attempts, limit_reached}
end

local increment = tonumber(ARGV[3])
attempts = redis.call("HINCRBY", KEYS[1], ARGV[1], increment)

return {"OK", attempts, limit_reached}
`)

func (s *redisStore) IncrementAttemptCounter(ctx context.Context, id string, limit int) (attempts int, limitReached bool, err error) {
	vals, err := script.Run(
		ctx,
		s.redis,
		[]string{s.generateKey(id)}, // KEYS
		"attempts",                  // ARGV[1]
		limit,                       // ARGV[2]
		1,                           // ARGV[3] increment
	).Slice()
	if err != nil {
		return -1, true, err
	}
	status := vals[0].(string)

	switch status {
	case "ERROR":
		errorStr := vals[1].(string)
		if errorStr == "FIELD_NOT_FOUND" {
			return 0, true, nil
		}

	case "OK":
		attempts = vals[1].(int)
		limitReached = vals[2].(bool)
		return attempts, limitReached, nil
	}

	return 0, true, fmt.Errorf("luo status erorr")
}

func (s *redisStore) generateKey(id string) string {
	return fmt.Sprint("otp:", id)
}

func (m OtpStoreModel) toKeyValueSlice() []string {
	return []string{
		"id", m.ID,
		"otp_hash", m.OtpHash,
		"channel", m.Channel.String(),
		"purpose", m.Purpose.String(),
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
	m.Purpose = otpPurpose(data["purpose"])
	m.Attempts = utils.Must(strconv.Atoi(data["attempts"]))
	m.CreatedAt = utils.Must(time.Parse(time.RFC3339, data["created_at"]))
	m.UpdatedAt = utils.Must(time.Parse(time.RFC3339, data["updated_at"]))
	m.ExpiresAt = utils.Must(time.Parse(time.RFC3339, data["expires_at"]))
	return m
}

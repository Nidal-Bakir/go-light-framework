package otp

import (
	"context"
	"time"

	"github.com/Nidal-Bakir/go-todo-backend/internal/database"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// hybridStore implements StoreProvider using both Redis and Database.
// Pattern: Cache-Aside (Lazy Loading)
// - Read: Try Redis → if miss, read DB → populate Redis
// - Write: Write DB (source of truth) → update Redis (best-effort)
// - Delete: Delete from both
type hybridStore struct {
	cache StoreProvider // Fast cache layer
	db    StoreProvider // Source of truth
}

func NewHybridStore(redis *redis.Client, db *database.Service) StoreProvider {
	return &hybridStore{cache: NewRedisStore(redis), db: NewDbStore(db)}
}

func (s *hybridStore) StoreOtpWithId(ctx context.Context, otpHash string, purpose OtpPurpose, channel OtpChannel, ExpiresAfter time.Duration, id uuid.UUID) error {
	err := s.db.StoreOtpWithId(ctx, otpHash, purpose, channel, ExpiresAfter, id)
	if err == nil {
		go s.cache.StoreOtpWithId(context.WithoutCancel(ctx), otpHash, purpose, channel, ExpiresAfter, id)
	}
	return err
}

func (s *hybridStore) StoreOtp(ctx context.Context, otpHash string, purpose OtpPurpose, channel OtpChannel, ExpiresAfter time.Duration) (id uuid.UUID, err error) {
	id = uuid.New()
	err = s.StoreOtpWithId(ctx, otpHash, purpose, channel, ExpiresAfter, id)
	return id, err
}

func (s *hybridStore) GetOtp(ctx context.Context, id uuid.UUID) (*OtpStoreModel, error) {
	if data, err := s.cache.GetOtp(ctx, id); data != nil && err == nil {
		return data, err
	}
	data, err := s.db.GetOtp(ctx, id)
	if err == nil {
		if ttl := time.Until(data.ExpiresAt); ttl > 0 {
			go s.cache.StoreOtpWithId(context.WithoutCancel(ctx), data.OtpHash, data.Purpose, data.Channel, ttl, id)
		}
	}
	return data, err
}

func (s *hybridStore) RemoveOtp(ctx context.Context, id uuid.UUID) error {
	err := s.db.RemoveOtp(ctx, id)
	if err == nil {
		go s.cache.RemoveOtp(context.WithoutCancel(ctx), id)
	}
	return err
}

func (s *hybridStore) IncrementAttemptCounter(ctx context.Context, id uuid.UUID, limit int) (attempts int, limitReached bool, err error) {
	attempts, limitReached, err = s.db.IncrementAttemptCounter(ctx, id, limit)
	if err == nil {
		go s.cache.IncrementAttemptCounter(context.WithoutCancel(ctx), id, limit)
	}
	return attempts, limitReached, err
}

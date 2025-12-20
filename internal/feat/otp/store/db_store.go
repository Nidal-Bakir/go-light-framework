package otp

import (
	"context"
	"time"

	"github.com/Nidal-Bakir/go-todo-backend/internal/database"
)

type dBStore struct {
	db *database.Service
}

func NewDBStore(db *database.Service) StoreProvider {
	return &dBStore{db}
}

func (s *dBStore) StoreOtp(ctx context.Context, otpHash string, channel otpChannel, ExpiresAfter time.Duration) (id string, err error) {

	return "", nil
}

func (s *dBStore) GetOtp(ctx context.Context, id string) (*OtpStoreModel, error) {
	return nil, nil
}

func (s *dBStore) RemoveOtp(ctx context.Context, id string) error {
	return nil
}

func (s *dBStore) IncrementAttemptCounter(ctx context.Context, id string, limit int) (int, error) {
	return 0, nil
}

package otp

import (
	"context"
	"time"

	"github.com/Nidal-Bakir/go-todo-backend/internal/database"
	"github.com/Nidal-Bakir/go-todo-backend/internal/database/database_queries"

	"github.com/google/uuid"
)

type dBStore struct {
	db *database.Service
}

func NewDBStore(db *database.Service) StoreProvider {
	return &dBStore{db}
}

func (s *dBStore) StoreOtp(ctx context.Context, otpHash string, purpose OtpPurpose, channel OtpChannel, ExpiresAfter time.Duration) (id uuid.UUID, err error) {
	otpId, err := s.db.Queries.OtpChallengeInsert(
		ctx,
		database_queries.OtpChallengeInsertParams{
			OtpHash:   otpHash,
			Channel:   channel.String(),
			Purpose:   purpose.String(),
			Attempts:  database.ToPgTypeInt4(1),
			ExpiresAt: database.ToPgTypeTimestamptz(time.Now().UTC().Add(ExpiresAfter)),
		},
	)
	return otpId, err
}

func (s *dBStore) GetOtp(ctx context.Context, id uuid.UUID) (*OtpStoreModel, error) {
	result, err := s.db.Queries.OtpChallengeGet(
		ctx,
		id,
	)
	if err != nil {
		if database.IsErrPgxNoRows(err) {
			return nil, NotFoundOTP
		}
		return nil, err
	}
	return otpStoreModelFromOtpChallengeDbModel(result), nil
}

func otpStoreModelFromOtpChallengeDbModel(m database_queries.OtpChallenge) *OtpStoreModel {
	return &OtpStoreModel{
		ID:        m.ID,
		OtpHash:   m.OtpHash,
		Attempts:  int(m.Attempts.Int32),
		Channel:   OtpChannel(m.Channel),
		Purpose:   OtpPurpose(m.Purpose),
		ExpiresAt: m.ExpiresAt.Time,
		CreatedAt: m.CreatedAt.Time,
		UpdatedAt: m.UpdatedAt.Time,
	}
}

func (s *dBStore) RemoveOtp(ctx context.Context, id uuid.UUID) error {
	return s.db.Queries.OtpChallengeDelete(ctx, id)
}

func (s *dBStore) IncrementAttemptCounter(ctx context.Context, id uuid.UUID, limit int) (attempts int, limitReached bool, err error) {
	result, err := s.db.Queries.OtpChallengeIncAttempt(
		ctx,
		database_queries.OtpChallengeIncAttemptParams{
			ID:            id,
			Inc:           database.ToPgTypeInt4(1),
			Attemptslimit: database.ToPgTypeInt4(int32(limit)),
		},
	)
	if err != nil {
		if database.IsErrPgxNoRows(err) {
			return limit, true, nil
		}
		return -1, true, err
	}
	return int(result.Int32), false, nil
}

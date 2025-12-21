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

func (s *dBStore) StoreOtp(ctx context.Context, otpHash string, purpose otpPurpose, channel otpChannel, ExpiresAfter time.Duration) (id string, err error) {
	otpId, err := s.db.Queries.OtpChallengeInsert(
		ctx,
		database_queries.OtpChallengeInsertParams{
			OtpHash:   otpHash,
			Channel:   channel.String(),
			Purpose:   purpose.String(),
			ExpiresAt: database.ToPgTypeTimestamptz(time.Now().Add(ExpiresAfter)),
		},
	)
	return otpId.String(), err
}

func (s *dBStore) GetOtp(ctx context.Context, id string) (*OtpStoreModel, error) {
	otpUUID, err := uuid.Parse(id)
	if err != nil {
		return nil, err
	}
	result, err := s.db.Queries.OtpChallengeGet(
		ctx,
		otpUUID,
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
		ID:        m.ID.String(),
		OtpHash:   m.OtpHash,
		Attempts:  int(m.Attempts.Int32),
		Channel:   otpChannel(m.Channel),
		Purpose:   otpPurpose(m.Purpose),
		ExpiresAt: m.ExpiresAt.Time,
		CreatedAt: m.CreatedAt.Time,
		UpdatedAt: m.UpdatedAt.Time,
	}
}

func (s *dBStore) RemoveOtp(ctx context.Context, id string) error {
	otpUUID, err := uuid.Parse(id)
	if err != nil {
		return err
	}
	return s.db.Queries.OtpChallengeDelete(ctx, otpUUID)
}

func (s *dBStore) IncrementAttemptCounter(ctx context.Context, id string, limit int) (attempts int, limitReached bool, err error) {
	otpUUID, err := uuid.Parse(id)
	if err != nil {
		return -1, true, err
	}
	result, err := s.db.Queries.OtpChallengeIncAttempt(
		ctx,
		database_queries.OtpChallengeIncAttemptParams{
			ID:            otpUUID,
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

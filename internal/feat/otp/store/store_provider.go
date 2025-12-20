package otp

import (
	"context"
	"time"
)

type StoreProvider interface {
	StoreOtp(ctx context.Context, otpHash string, channel otpChannel, ExpiresAfter time.Duration) (id string, err error)
	GetOtp(ctx context.Context, id string) (*OtpStoreModel, error)
	RemoveOtp(ctx context.Context, id string) error
	IncrementAttemptCounter(ctx context.Context, id string, limit int) (int, error)
}

type otpChannel string

func (c otpChannel) String() string {
	return string(c)
}

const (
	EmailChannel otpChannel = "email"
	SMSChannel   otpChannel = "sms"
)

type OtpStoreModel struct {
	ID        string
	OtpHash   string
	Channel   otpChannel
	Attempts  int
	CreatedAt time.Time
	UpdatedAt time.Time
	ExpiresAt time.Time
}

package otp

import (
	"context"
	"time"
)

type StoreProvider interface {
	StoreOtp(ctx context.Context, otpHash string, purpose otpPurpose, channel otpChannel, ExpiresAfter time.Duration) (id string, err error)
	GetOtp(ctx context.Context, id string) (*OtpStoreModel, error)
	RemoveOtp(ctx context.Context, id string) error
	IncrementAttemptCounter(ctx context.Context, id string, limit int) (attempts int, limitReached bool, err error)
}

type otpChannel string
type otpPurpose string

const (
	EmailChannel otpChannel = "email"
	SMSChannel   otpChannel = "sms"

	AccountVerification otpPurpose = "account_verification"
	ResetPassword       otpPurpose = "reset_password"
)

func (c otpChannel) String() string {
	return string(c)
}
func (o otpPurpose) String() string {
	return string(o)
}

type OtpStoreModel struct {
	ID        string
	OtpHash   string
	Purpose   otpPurpose
	Channel   otpChannel
	Attempts  int
	CreatedAt time.Time
	UpdatedAt time.Time
	ExpiresAt time.Time
}

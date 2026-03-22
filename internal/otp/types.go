package otp

import (
	"time"

	"github.com/Nidal-Bakir/go-todo-backend/internal/l10n"
	"github.com/Nidal-Bakir/go-todo-backend/internal/utils/email"
	"github.com/Nidal-Bakir/go-todo-backend/internal/utils/phonenumber"
	"github.com/google/uuid"
)

type OtpChannel string
type OtpPurpose string

const (
	EmailChannel OtpChannel = "email"
	SMSChannel   OtpChannel = "sms"

	AccountVerification OtpPurpose = "account_verification"
	ResetPassword       OtpPurpose = "reset_password"
	MfaVerification     OtpPurpose = "mfa_verification"
	MfaEmailOtp         OtpPurpose = "mfa_email_otp"
	MfaPhoneOtp         OtpPurpose = "mfa_phone_otp"
)

func (c OtpChannel) String() string {
	return string(c)
}

func (o OtpPurpose) String() string {
	return string(o)
}

type OtpStoreModel struct {
	ID        uuid.UUID
	OtpHash   string
	Purpose   OtpPurpose
	Channel   OtpChannel
	Attempts  int
	CreatedAt time.Time
	UpdatedAt time.Time
	ExpiresAt time.Time
}

type Options struct {
	PhoneTarget *phonenumber.PhoneNumber
	EmailTarget *email.Email
	Localizer   *l10n.Localizer
	Purpose     OtpPurpose
	Otp         string
}

package otp

import (
	"time"

	"github.com/Nidal-Bakir/go-todo-backend/internal/l10n"
	"github.com/Nidal-Bakir/go-todo-backend/internal/utils/email"
	"github.com/Nidal-Bakir/go-todo-backend/internal/utils/phonenumber"
)

type OtpChannel string
type OtpPurpose string

const (
	EmailChannel OtpChannel = "email"
	SMSChannel   OtpChannel = "sms"

	AccountVerification OtpPurpose = "account_verification"
	ResetPassword       OtpPurpose = "reset_password"
)

func (c OtpChannel) String() string {
	return string(c)
}

func (o OtpPurpose) String() string {
	return string(o)
}

type OtpStoreModel struct {
	ID        string
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

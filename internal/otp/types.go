package otp

import (
	"fmt"
	"time"

	"github.com/Nidal-Bakir/go-todo-backend/internal/apperr"
	"github.com/Nidal-Bakir/go-todo-backend/internal/l10n"
	"github.com/Nidal-Bakir/go-todo-backend/internal/utils/email"
	"github.com/Nidal-Bakir/go-todo-backend/internal/utils/phonenumber"
	"github.com/google/uuid"
)

type (
	OtpChannel    string
	OtpPurpose    string
	TotpAlgorithm string
	TotpDigits    uint8
)

const (
	EmailChannel OtpChannel = "email"
	SMSChannel   OtpChannel = "sms"

	AccountVerification  OtpPurpose = "account_verification"
	ResetPassword        OtpPurpose = "reset_password"
	MfaEmailVerification OtpPurpose = "mfa_email_verification"
	MfaPhoneVerification OtpPurpose = "mfa_phone_verification"
	MfaEmailOtp          OtpPurpose = "mfa_email_otp"
	MfaPhoneOtp          OtpPurpose = "mfa_phone_otp"

	SHA1   TotpAlgorithm = "SHA-1" // default
	SHA256 TotpAlgorithm = "SHA-256"
	SHA512 TotpAlgorithm = "SHA-512"
	MD5    TotpAlgorithm = "MD5"

	DigitsSix   TotpDigits = 6 // default
	DigitsEight TotpDigits = 8
)

func (c OtpChannel) String() string {
	return string(c)
}

func (o OtpPurpose) String() string {
	return string(o)
}

func (a TotpAlgorithm) String() string {
	return string(a)
}

func (a TotpDigits) Val() uint {
	return uint(a)
}

func (l *OtpPurpose) FromString(str string) (*OtpPurpose, error) {
	switch {
	case AccountVerification.String() == str:
		*l = AccountVerification
	case ResetPassword.String() == str:
		*l = ResetPassword
	case MfaEmailVerification.String() == str:
		*l = MfaEmailVerification
	case MfaPhoneVerification.String() == str:
		*l = MfaPhoneVerification
	case MfaEmailOtp.String() == str:
		*l = MfaEmailOtp
	case MfaPhoneOtp.String() == str:
		*l = MfaPhoneOtp
	default:
		l = nil
		return l, apperr.ErrUnsupportedLoginIdentityType
	}
	return l, nil
}

func (l *OtpPurpose) Fold(actions OtpPurposeFoldActions) {
	panicFn := func() {
		panic(fmt.Sprintf("Not supported otp purpose type %s", l.String()))
	}
	if l == nil {
		panicFn()
		return
	}
	l.FoldOr(actions, panicFn)
}

func (l *OtpPurpose) FoldOr(actions OtpPurposeFoldActions, orElse func()) {
	if l == nil {
		orElse()
		return
	}

	actionOrElse := func(fn func()) func() {
		if fn == nil {
			return orElse
		}
		return fn
	}

	switch *l {
	case AccountVerification:
		actionOrElse(actions.OnAccountVerification)()
	case ResetPassword:
		actionOrElse(actions.OnResetPassword)()
	case MfaEmailVerification:
		actionOrElse(actions.OnMfaEmailVerification)()
	case MfaPhoneVerification:
		actionOrElse(actions.OnMfaPhoneVerification)()
	case MfaEmailOtp:
		actionOrElse(actions.OnMfaEmailOtp)()
	case MfaPhoneOtp:
		actionOrElse(actions.OnMfaPhoneOtp)()

	default:
		orElse()
	}
}

type OtpPurposeFoldActions struct {
	OnAccountVerification  func()
	OnResetPassword        func()
	OnMfaEmailVerification func()
	OnMfaPhoneVerification func()
	OnMfaEmailOtp          func()
	OnMfaPhoneOtp          func()
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

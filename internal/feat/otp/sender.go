package otp

import (
	"context"
	"errors"
	"math/rand/v2"
	"strings"

	"github.com/Nidal-Bakir/go-todo-backend/internal/gateway"
	"github.com/Nidal-Bakir/go-todo-backend/internal/utils"
	"github.com/Nidal-Bakir/go-todo-backend/internal/utils/email"
	"github.com/Nidal-Bakir/go-todo-backend/internal/utils/phonenumber"
)

const (
	otpChars = "0123456789"
)

type Sender struct {
	providerFactory gateway.ProviderFactory
	otpLength       uint8
}

func NewSender(_ context.Context, provider gateway.ProviderFactory, otpLength uint8) *Sender {
	utils.Assert(otpLength >= 3, "you can not have otp with length less then 2")
	return &Sender{providerFactory: provider, otpLength: otpLength}
}

func (o Sender) SendOTP(ctx context.Context, option Options) (err error) {
	var content string

	switch option.Purpose {
	case AccountVerification:
		content = option.Otp
	case ResetPassword:
		content = option.Otp
	}

	if option.PhoneTarget != nil {
		phoneErr := o.sendSmsOtp(ctx, option.PhoneTarget, content)
		err = phoneErr
	}

	if option.EmailTarget != nil {
		emailErr := o.sendEmailOtp(ctx, option.EmailTarget, content)
		err = errors.Join(emailErr, err)
	}

	return err
}

func (o Sender) sendSmsOtp(ctx context.Context, target *phonenumber.PhoneNumber, content string) (err error) {
	return o.providerFactory.NewSMSProvider(ctx, target.CountryCode()).Send(ctx, target.ToE164(), content)
}

func (o Sender) sendEmailOtp(ctx context.Context, target *email.Email, content string) (err error) {
	return o.providerFactory.NewEmailProvider(ctx).Send(ctx, target.String(), content)
}

func (o Sender) GenRandOTP() string {
	strBuild := strings.Builder{}
	for range o.otpLength {
		otpChar := otpChars[rand.IntN(len(otpChars))]
		strBuild.WriteRune(rune(otpChar))
	}
	return strBuild.String()
}

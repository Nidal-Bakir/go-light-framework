package otp

import (
	"image"
	"time"

	"github.com/Nidal-Bakir/go-todo-backend/internal/encryption"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func NewTotpKey(accountKey, issuer string) (*TotpKey, error) {
	key, err := totp.Generate(
		totp.GenerateOpts{
			Issuer:      issuer,
			AccountName: accountKey,
			Digits:      otp.DigitsSix,
			Algorithm:   otp.AlgorithmSHA1,
			Period:      30,
			SecretSize:  20,
		})
	return &TotpKey{key: key}, err
}

func ValidateTotp(passcode, encryptedSecretKey string) bool {
	plainSecretKey, err := encryption.DefaultAesCipher().Decrypt(encryptedSecretKey)
	if err != nil {
		return false
	}
	return ValidateTotpPlain(passcode, plainSecretKey)
}

func ValidateTotpPlain(passcode, plainSecretKey string) bool {
	rv, _ := totp.ValidateCustom(
		passcode,
		plainSecretKey,
		time.Now().UTC(),
		totp.ValidateOpts{
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
			Period:    30,
			Skew:      1,
		},
	)
	return rv
}

type TotpKey struct {
	key *otp.Key
}

func (k *TotpKey) AccountName() string {
	return k.key.AccountName()
}

func (k *TotpKey) Algorithm() TotpAlgorithm {
	switch k.key.Algorithm() {
	case otp.AlgorithmMD5:
		return MD5
	case otp.AlgorithmSHA1:
		return SHA1
	case otp.AlgorithmSHA256:
		return SHA256
	case otp.AlgorithmSHA512:
		return SHA512
	default:
		panic("unexpected otp.Algorithm")
	}
}

func (k *TotpKey) Digits() TotpDigits {
	switch k.key.Digits() {
	case otp.DigitsEight:
		return DigitsEight
	case otp.DigitsSix:
		return DigitsSix
	default:
		panic("unexpected otp.Digits")
	}
}

func (k *TotpKey) Image(dimension int) (image.Image, error) {
	return k.key.Image(dimension, dimension)
}

func (k *TotpKey) Issuer() string {
	return k.key.Issuer()
}

func (k *TotpKey) Period() uint32 {
	return uint32(k.key.Period())
}

func (k *TotpKey) SecretKey() string {
	return k.key.Secret()
}

func (k *TotpKey) EncryptedSecretKey() (string, error) {
	return encryption.DefaultAesCipher().Encrypt(k.SecretKey())
}

func (k *TotpKey) String() string {
	return k.key.String()
}

func (k *TotpKey) URL() string {
	return k.key.URL()
}

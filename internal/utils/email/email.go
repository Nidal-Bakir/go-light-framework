package email

import (
	"net/mail"
	"strings"

	"github.com/Nidal-Bakir/go-todo-backend/internal/apperr"
)

type Email struct {
	email *mail.Address
}

func Parse(email string) (*Email, error) {
	a, err := mail.ParseAddress(email)
	if err != nil || a.Address != email || a == nil {
		return nil, apperr.ErrInvalidEmail
	}
	return &Email{email: a}, nil
}

func MustParse(email string) *Email {
	e, err := Parse(email)
	if err != nil {
		panic(err)
	}
	return e
}

func (e *Email) String() string {
	return e.email.Address
}

// Masked returns the email address with the local part partially masked
// for privacy-preserving display.
//
// Rules:
//   - Shows first 3 characters of local part, masks the rest with '*'
//   - Domain is shown in full (e.g., gmail.com)
//   - If local part ≤3 chars, entire local part is masked
//   - Returns "****@***.***" for malformed emails
//
// Examples:
//
//	john.doe@gmail.com    → "joh*****@gmail.com"
//	ab@test.com           → "**@test.com"
//	a@company.co.uk       → "*@company.co.uk"
//	invalid-email         → "****@***.***"
//
// Note: This is for display only; the original email remains unchanged.
func (e *Email) Masked() string {
	splitedEmail := strings.Split(e.email.Address, "@")
	if len(splitedEmail) != 2 {
		return "****@***.***" // fallback for invalid emails
	}
	local, domain := splitedEmail[0], splitedEmail[1]
	l := len(local)
	if l <= 3 {
		return strings.Repeat("*", l) + "@" + domain
	}
	return local[:3] + strings.Repeat("*", l-3) + "@" + domain
}

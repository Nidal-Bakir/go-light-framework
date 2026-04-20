package email

import (
	"net/mail"

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

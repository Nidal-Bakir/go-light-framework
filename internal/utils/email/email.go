package email

import (
	"net/mail"
	"strings"

	"github.com/Nidal-Bakir/go-todo-backend/internal/apperr"
)

type Email struct {
	email string
}

func New(email string) *Email {
	return &Email{email: strings.ToLower(email)}
}

func (e *Email) String() string {
	return e.email
}

func (e *Email) IsValidEmail() bool {
	a, err := mail.ParseAddress(e.email)
	return err == nil && a.Address == e.email
}

func (e *Email) IsValidEmailErr() error {
	if e.IsValidEmail() {
		return nil
	}
	return apperr.ErrInvalidEmail
}

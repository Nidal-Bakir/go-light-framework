package gateway

import (
	"context"
	"fmt"

	"github.com/Nidal-Bakir/go-todo-backend/internal/utils/email"
	"github.com/rs/zerolog"
)

type simpleEmailProvider struct{}

func (p simpleEmailProvider) Send(ctx context.Context, target, content string) error {
	fmt.Println(target)
	emailAddress, err := email.Parse(target)
	if err != nil {
		return err
	}
	zerolog.Ctx(ctx).Debug().Str("target", emailAddress.String()).Str("content", content).Msg("Sending Email")
	return nil
}

func newEmailProvider() Sender {
	return new(simpleEmailProvider)
}

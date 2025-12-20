package gateway

import "context"

type Sender interface {
	Send(ctx context.Context, target, content string) error
}

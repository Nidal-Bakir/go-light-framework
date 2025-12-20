package gateway

import (
	"context"
)

type ProviderFactory interface {
	NewSMSProvider(ctx context.Context, contryCode int) Sender
	NewEmailProvider(ctx context.Context) Sender
}

func NewProviderFactory(ctx context.Context) ProviderFactory {
	return new(providerImpl)
}

type providerImpl struct {
}

func (p providerImpl) NewSMSProvider(ctx context.Context, contryCode int) Sender {
	return newSMSProvider(contryCode)
}

func (p providerImpl) NewEmailProvider(ctx context.Context) Sender {
	return newEmailProvider()
}

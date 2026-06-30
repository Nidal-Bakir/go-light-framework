package oidc

import (
	"context"

	"github.com/Nidal-Bakir/go-todo-backend/internal/encryption"
	oauth "github.com/Nidal-Bakir/go-todo-backend/internal/feat/auth/oauth/utils"
)

type OidcFunc func(ctx context.Context, code, codeVerifier, oidcToken string) (*OidcData, error)

func (f OidcFunc) Exec(ctx context.Context, code, codeVerifier, oidcToken string) (*OidcData, error) {
	return f(ctx, code, codeVerifier, oidcToken)
}

// encrypt the access and refresh tokens
func (f OidcFunc) ExecEncrypted(ctx context.Context, code, codeVerifier, oidcToken string, cipher encryption.Chipher) (*OidcData, error) {
	data, err := f(ctx, code, codeVerifier, oidcToken)
	if err != nil {
		return data, err
	}
	if data.OauthAccessToken.Valid {
		enc, err := cipher.Encrypt(data.OauthAccessToken.String)
		if err != nil {
			return data, err
		}
		data.OauthAccessToken.String = enc
	}
	if data.OauthRefreshToken.Valid {
		enc, err := cipher.Encrypt(data.OauthRefreshToken.String)
		if err != nil {
			return data, err
		}
		data.OauthRefreshToken.String = enc
	}
	return data, err
}

func NewOidc(provider oauth.OauthProvider) OidcFunc {
	var fn OidcFunc
	provider.Fold(
		oauth.OauthProviderFoldActions{
			OnGoogle: func() error {
				fn = googleOidcFunc
				return nil
			},
		},
	)
	return fn
}

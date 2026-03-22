package session

import (
	"context"
	"fmt"
	"time"

	"github.com/Nidal-Bakir/go-todo-backend/internal/utils/appjwt"
)

func NewJwtSessionProvider(appjwt *appjwt.AppJWT, storeProvider StoreProvider) SessionProvider {
	return &jwtSessionProvider{appjwt: appjwt, storeProvider: storeProvider}
}

type jwtSessionProvider struct {
	appjwt        *appjwt.AppJWT
	storeProvider StoreProvider
}

func (j jwtSessionProvider) NewSession(ctx context.Context, options ...option) (Session, error) {
	l := len(options)
	m := make(map[string]any, l)
	for i := 0; i < l; i++ {
		options[i](m)
	}

	exp, ok := m["jwt_expires_at"].(time.Time)
	if !ok {
		exp = time.Now().UTC()
	}
	delete(m, "jwt_expires_at")

	subject, ok := m["jwt_subject"].(string)
	if !ok {
		subject = ""
	}
	delete(m, "jwt_subject")

	claims := make(map[string]string, len(m))
	for k, v := range m {
		switch val := v.(type) {
		case time.Time:
			claims[k] = val.Format(time.RFC3339)
		case nil:
			claims[k] = ""
		default:
			claims[k] = fmt.Sprintf("%v", val)
		}
	}

	jwtTokenRawString, customClaims, err := j.appjwt.GenWithClaims(exp, claims, subject)
	if err != nil {
		return nil, err
	}

	return newJwtSession(jwtTokenRawString, customClaims, j.storeProvider), nil
}

func (j jwtSessionProvider) ParseSession(ctx context.Context, rawSession string, options ...option) (Session, error) {
	l := len(options)
	m := make(map[string]any, l)
	for i := 0; i < l; i++ {
		options[i](m)
	}

	subject, ok := m["jwt_subject"].(string)
	if !ok {
		subject = ""
	}
	delete(m, "jwt_subject")

	customClaims, err := j.appjwt.VerifyToken(rawSession, subject)
	if err != nil {
		return nil, err
	}

	return newJwtSession(rawSession, *customClaims, j.storeProvider), nil
}

// ================================================

func AddJwtClaim(key, claim string) option {
	return func(m map[string]any) {
		m[key] = claim
	}
}

func AddSubjectJwtClaim(subject string) option {
	return AddJwtClaim("jwt_subject", subject)
}

func AddExpiresAtJwtClaim(expiresAt time.Time) option {
	return func(m map[string]any) {
		m["jwt_expires_at"] = expiresAt
	}
}

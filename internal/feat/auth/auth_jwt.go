package auth

import (
	"strconv"
	"time"

	"github.com/Nidal-Bakir/go-todo-backend/internal/utils/appjwt"
	"github.com/golang-jwt/jwt/v5"
)

const (
	userIdKey         = "user_id"
	sessionPurposeKey = "session_purpose"

	installationSubject = "installation"
	installationIdKey   = "installation_id"
)

type AuthJWT struct {
	appjwt *appjwt.AppJWT
}

func NewAuthJWT(appjwt *appjwt.AppJWT) *AuthJWT {
	return &AuthJWT{appjwt: appjwt}
}

// ---------------------------------------------------------------------

type AuthClaims struct {
	UserId         int32
	SessionPurpose SessionPurpose
	jwt.RegisteredClaims
}

func (a AuthClaims) toMap() map[string]string {
	m := make(map[string]string)
	m[userIdKey] = strconv.Itoa(int(a.UserId))
	m[sessionPurposeKey] = a.SessionPurpose.String()
	return m
}

func (authJWT AuthJWT) GenrateAuthToken(userId int32, expiresAt time.Time, sessionPurpose SessionPurpose) (string, error) {
	authClaims := AuthClaims{UserId: userId, SessionPurpose: sessionPurpose}
	return authJWT.appjwt.GenWithClaims(expiresAt, authClaims.toMap(), sessionPurpose.String())
}

func (authJWT AuthJWT) VerifyAuthToken(token string, sessionPurpose SessionPurpose) (*AuthClaims, error) {
	c, err := authJWT.appjwt.VerifyToken(token, sessionPurpose.String())
	if err != nil {
		return nil, err
	}

	userId, err := strconv.Atoi(c.Claims[userIdKey])
	if err != nil {
		return nil, err
	}

	return &AuthClaims{
			UserId:           int32(userId),
			SessionPurpose:   SessionPurpose(c.Claims[sessionPurposeKey]),
			RegisteredClaims: c.RegisteredClaims,
		},
		nil
}

// ---------------------------------------------------------------------

type InstallationClaims struct {
	jwt.RegisteredClaims
}

func (a InstallationClaims) toMap() map[string]string {
	m := make(map[string]string)
	return m
}

func (authJWT AuthJWT) GenerateInstallationToken(expiresAt time.Time) (string, error) {
	installationClaims := InstallationClaims{}
	return authJWT.appjwt.GenWithClaims(expiresAt, installationClaims.toMap(), installationSubject)
}

func (authJWT AuthJWT) VerifyInstallationToken(token string) (*InstallationClaims, error) {
	c, err := authJWT.appjwt.VerifyToken(token, installationSubject)
	if err != nil {
		return nil, err
	}

	return &InstallationClaims{RegisteredClaims: c.RegisteredClaims}, nil
}

// ---------------------------------------------------------------------

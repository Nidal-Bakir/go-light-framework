package auth

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"time"

	"github.com/Nidal-Bakir/go-todo-backend/internal/apperr"
	"github.com/Nidal-Bakir/go-todo-backend/internal/database/database_queries"
	"github.com/Nidal-Bakir/go-todo-backend/internal/feat/auth/oauth/oidc"
	oauth "github.com/Nidal-Bakir/go-todo-backend/internal/feat/auth/oauth/utils"
	"github.com/Nidal-Bakir/go-todo-backend/internal/session"
	"github.com/Nidal-Bakir/go-todo-backend/internal/utils"
	"github.com/Nidal-Bakir/go-todo-backend/internal/utils/email"
	"github.com/Nidal-Bakir/go-todo-backend/internal/utils/phonenumber"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

type SessionPurpose string

const (
	SessionPurposeLogin SessionPurpose = "login"
	SessionPurposeMFA   SessionPurpose = "mfa"
)

func (s SessionPurpose) String() string {
	return string(s)
}

type MfaSessionPurpose string

const (
	MfaSessionPurposeLogin          MfaSessionPurpose = "login"
	MfaSessionPurposeUpdatePassword MfaSessionPurpose = "update_password"
)

func (s MfaSessionPurpose) String() string {
	return string(s)
}

type MfaStatus string

const (
	MfaStatusPending  MfaStatus = "pending"
	MfaStatusVerified MfaStatus = "verified"
	MfaStatusDisabled MfaStatus = "disabled"
	MfaStatusRevoked  MfaStatus = "revoked"
)

func (s MfaStatus) String() string {
	return string(s)
}

type MfaMethodType string

const (
	MfaMethodTypeEmail    MfaMethodType = "email"
	MfaMethodTypePhone    MfaMethodType = "phone"
	MfaMethodTypeTotp     MfaMethodType = "totp"
	MfaMethodTypeWebauthn MfaMethodType = "webauthn"
)

func (s MfaMethodType) String() string {
	return string(s)
}

type LoginIdentityType string

const (
	LoginIdentityTypeEmail LoginIdentityType = "email"
	LoginIdentityTypePhone LoginIdentityType = "phone"
	LoginIdentityTypeOcid  LoginIdentityType = "ocid"
	LoginIdentityTypeGuest LoginIdentityType = "guest"
)

func (l LoginIdentityType) IsUsingEmail() bool {
	return l == LoginIdentityTypeEmail
}

func (l LoginIdentityType) IsUsingPhoneNumber() bool {
	return l == LoginIdentityTypePhone
}

func (l LoginIdentityType) SupportPassword() bool {
	var supportPassword bool
	l.FoldOr(
		LoginIdentityFoldActions{
			OnEmail: func() { supportPassword = true },
			OnPhone: func() { supportPassword = true },
		},
		func() {},
	)
	return supportPassword
}

func (l LoginIdentityType) String() string {
	return string(l)
}

func (l *LoginIdentityType) FromString(str string) (*LoginIdentityType, error) {
	switch {
	case LoginIdentityTypeEmail.String() == str:
		*l = LoginIdentityTypeEmail

	case LoginIdentityTypePhone.String() == str:
		*l = LoginIdentityTypePhone

	default:
		l = nil
		return l, apperr.ErrUnsupportedLoginIdentityType
	}

	return l, nil
}

func (l *LoginIdentityType) Fold(actions LoginIdentityFoldActions) {
	panicFn := func() {
		panic(fmt.Sprintf("Not supported login identity type %s", l.String()))
	}

	if l == nil {
		panicFn()
		return
	}

	l.FoldOr(actions, panicFn)
}

type LoginIdentityFoldActions struct {
	OnEmail func()
	OnPhone func()
	OnOcid  func()
	OnGuest func()
}

func (l *LoginIdentityType) FoldOr(actions LoginIdentityFoldActions, orElse func()) {
	if l == nil {
		orElse()
		return
	}

	actionOrElse := func(fn func()) func() {
		if fn == nil {
			return orElse
		}
		return fn
	}

	switch *l {
	case LoginIdentityTypeEmail:
		actionOrElse(actions.OnEmail)()

	case LoginIdentityTypePhone:
		actionOrElse(actions.OnPhone)()

	case LoginIdentityTypeOcid:
		actionOrElse(actions.OnOcid)()

	case LoginIdentityTypeGuest:
		actionOrElse(actions.OnGuest)()

	default:
		orElse()
	}
}

type DeviceOS string

const (
	DeviceOSAndroid  DeviceOS = "android"
	DeviceOSIos      DeviceOS = "ios"
	DeviceOSWindows  DeviceOS = "windows"
	DeviceOSMacos    DeviceOS = "macos"
	DeviceOSLinux    DeviceOS = "linux"
	DeviceOSChromeos DeviceOS = "chromeos"
	DeviceOSUnknown  DeviceOS = "unknown"
)

var DevicesOSs = []DeviceOS{
	DeviceOSAndroid,
	DeviceOSIos,
	DeviceOSWindows,
	DeviceOSMacos,
	DeviceOSLinux,
	DeviceOSChromeos,
	DeviceOSUnknown,
}

func (os DeviceOS) String() string {
	return string(os)
}

func (os *DeviceOS) FromString(str string) (*DeviceOS, error) {
	switch {
	case DeviceOSAndroid.String() == str:
		*os = DeviceOSAndroid
	case DeviceOSIos.String() == str:
		*os = DeviceOSIos
	case DeviceOSWindows.String() == str:
		*os = DeviceOSWindows
	case DeviceOSMacos.String() == str:
		*os = DeviceOSMacos
	case DeviceOSLinux.String() == str:
		*os = DeviceOSLinux
	case DeviceOSChromeos.String() == str:
		*os = DeviceOSChromeos
	case DeviceOSUnknown.String() == str:
		*os = DeviceOSUnknown
	default:
		os = nil
		return os, errors.New("invalid device os")
	}
	return os, nil
}

type ClientType string

const (
	ClientTypeWeb      ClientType = "web"
	ClientTypeMobile   ClientType = "mobile"
	ClientTypeEmbedded ClientType = "embedded"
)

var clientTypes = []ClientType{ClientTypeWeb, ClientTypeMobile, ClientTypeEmbedded}

func (c ClientType) String() string {
	return string(c)
}

func (c ClientType) IsWeb() bool {
	return c == ClientTypeWeb
}

func (c *ClientType) FromString(str string) (*ClientType, error) {
	switch {
	case ClientTypeWeb.String() == str:
		*c = ClientTypeWeb
	case ClientTypeMobile.String() == str:
		*c = ClientTypeMobile
	case ClientTypeEmbedded.String() == str:
		*c = ClientTypeEmbedded
	default:
		c = nil
		return c, errors.New("invalid client type")
	}
	return c, nil
}

type TempPasswordUser struct {
	Id                uuid.UUID // used as a key
	Username          string    // will be the same as Id and will be updated with new value afterword, but initaly this should not be empty
	LoginIdentityType LoginIdentityType
	Fname             string
	Lname             string
	Email             *email.Email
	Phone             *phonenumber.PhoneNumber
	OtpId             uuid.UUID
	Password          string
}

func (tu TempPasswordUser) ToMap() map[string]string {
	m := make(map[string]string, 8)
	m["id"] = tu.Id.String()
	m["username"] = tu.Username
	m["login_identity_type"] = tu.LoginIdentityType.String()
	m["f_name"] = tu.Fname
	m["l_name"] = tu.Lname
	tu.LoginIdentityType.Fold(
		LoginIdentityFoldActions{
			OnEmail: func() { m["email"] = tu.Email.String() },
			OnPhone: func() {
				if tu.Phone != nil {
					m["phone_number"] = tu.Phone.ToE164()
				}
			},
		},
	)
	m["otp_id"] = tu.OtpId.String()
	m["password"] = tu.Password
	return m
}

func (tu *TempPasswordUser) FromMap(m map[string]string) *TempPasswordUser {
	tu.Id = uuid.MustParse(m["id"])
	tu.Username = m["username"]
	tu.LoginIdentityType = LoginIdentityType(m["login_identity_type"])
	tu.LoginIdentityType.Fold(
		LoginIdentityFoldActions{
			OnEmail: func() { tu.Email = email.MustParse(m["email"]) },
			OnPhone: func() { tu.Phone = phonenumber.MustParse(m["phone_number"]) },
		},
	)
	tu.Fname = m["f_name"]
	tu.Lname = m["l_name"]
	tu.OtpId = uuid.MustParse(m["otp_id"])
	tu.Password = m["password"]
	return tu
}

func (tu TempPasswordUser) ValidateForStore() (ok bool) {
	ok = tu.Username == tu.Id.String()

	tu.LoginIdentityType.FoldOr(
		LoginIdentityFoldActions{
			OnEmail: func() { ok = ok && tu.Email != nil },
			OnPhone: func() { ok = ok && tu.Phone.IsValidPhoneNumber() },
		},
		func() { ok = false },
	)

	ok = ok && len(tu.Fname) != 0
	ok = ok && len(tu.Lname) != 0
	ok = ok && len(tu.Password) >= PasswordRecommendedLength

	return ok
}

type CreatePasswordUserArgs struct {
	Username          string
	Fname             string
	Lname             string
	LoginIdentityType LoginIdentityType
	Email             *email.Email
	Phone             *phonenumber.PhoneNumber
	HashedPass        string
	PassSalt          string
	ProfileImagePath  string
	RoleName          string
	VerifiedAt        time.Time
}

type User struct {
	ID            int32              `json:"id"`
	Username      string             `json:"username"`
	ProfileImage  pgtype.Text        `json:"profile_image"`
	FirstName     string             `json:"first_name"`
	LastName      pgtype.Text        `json:"last_name"`
	CreatedAt     pgtype.Timestamptz `json:"created_at"`
	InfoUpdatedAt pgtype.Timestamptz `json:"info_updated_at"`
	BlockedAt     pgtype.Timestamptz `json:"blocked_at"`
	DeletedAt     pgtype.Timestamptz `json:"deleted_at"`
	RoleName      pgtype.Text        `json:"role_name"`
}

func NewUserFromDatabaseUser(u database_queries.UserWithInfo) User {
	return User{
		ID:            u.ID,
		Username:      u.Username,
		ProfileImage:  u.ProfileImage,
		FirstName:     u.FirstName,
		LastName:      u.LastName,
		CreatedAt:     u.CreatedAt,
		InfoUpdatedAt: u.InfoUpdatedAt,
		BlockedAt:     u.BlockedAt,
		DeletedAt:     u.DeletedAt,
		RoleName:      u.RoleName,
	}
}

type UserAndSession struct {
	UserID           int32
	UserBlockedAt    pgtype.Timestamptz
	UserBlockedUntil pgtype.Timestamptz
	UserRoleName     pgtype.Text

	SessionID               int64
	SessionOriginatedFrom   int32
	SessionUsedInstallation int32
	SessionPurpose          SessionPurpose
	SessionToken            session.Session
}

func NewUserAndSessionFromDatabaseUserAndSessionRow(u database_queries.UsersGetUserAndSessionDataBySessionTokenRow, sessionToken session.Session) UserAndSession {
	return UserAndSession{
		UserID:           u.UserID,
		UserBlockedAt:    u.UserBlockedAt,
		UserBlockedUntil: u.UserBlockedUntil,
		UserRoleName:     u.UserRoleName,

		SessionID:               u.SessionID,
		SessionOriginatedFrom:   u.SessionOriginatedFrom,
		SessionUsedInstallation: u.SessionUsedInstallation,
		SessionPurpose:          SessionPurpose(u.SessionPurpose),
		SessionToken:            sessionToken,
	}
}

type ForgetPasswordTmpDataStore struct {
	Id uuid.UUID // used as a key

	UserId int
	OtpId  uuid.UUID
}

func (f ForgetPasswordTmpDataStore) ToMap() map[string]string {
	m := make(map[string]string, 8)
	m["id"] = f.Id.String()
	m["user_id"] = strconv.Itoa(f.UserId)
	m["otp_id"] = f.OtpId.String()
	return m
}

func (f *ForgetPasswordTmpDataStore) FromMap(m map[string]string) *ForgetPasswordTmpDataStore {
	f.Id = uuid.MustParse(m["id"])
	f.UserId = utils.Must(strconv.Atoi(m["user_id"]))
	f.OtpId = uuid.MustParse(m["otp_id"])
	return f
}

type PasswordLoginAccessKey struct {
	Phone             *phonenumber.PhoneNumber
	Email             *email.Email
	LoginIdentityType LoginIdentityType
}

func (p PasswordLoginAccessKey) accessKeyStr() string {
	a := ""
	p.LoginIdentityType.Fold(
		LoginIdentityFoldActions{
			OnEmail: func() { a = p.Email.String() },
			OnPhone: func() { a = p.Phone.ToE164() },
		},
	)
	return a
}

type CreateInstallationData struct {
	NotificationToken       string     // e.g the FCM token
	Locale                  string     // e.g: en-US ...
	TimezoneOffsetInMinutes int        // e.g: +180
	DeviceManufacturer      string     // e.g: samsung
	DeviceOS                DeviceOS   // e.g: android
	ClientType              ClientType // e.g: mobile/web/...
	DeviceOSVersion         string     // e.g: 14
	AppVersion              string     // e.g: 3.1.1
}

type UpdateInstallationData struct {
	NotificationToken       string // e.g the FCM token
	Locale                  string // e.g: en-US ...
	TimezoneOffsetInMinutes int    // e.g: +180
	AppVersion              string // e.g: 3.1.1
}

type PublicLoginOptionForProfile struct {
	ID                int32
	Phone             *phonenumber.PhoneNumber
	Email             *email.Email
	LoginIdentityType LoginIdentityType
	IsVerified        bool
	OidcProvider      string
}

type LoginOrCreateUserWithOidcData struct {
	oauthProvider      oauth.OauthProvider
	OauthTokenIssuedAt pgtype.Timestamp
	UserUsername       string
	InstallationId     int32
	IpAddress          netip.Addr

	*oidc.OidcData
}

type LoginOrCreateUserWithOidcRepoParam struct {
	OauthProvider oauth.OauthProvider
	Code          string
	CodeVerifier  string
	OidcToken     string
}

type Installation struct {
	ID                      int32      `json:"id"`
	InstallationToken       string     `json:"installation_token"`
	NotificationToken       string     `json:"notification_token"`
	Locale                  string     `json:"locale"`
	TimezoneOffsetInMinutes int32      `json:"timezone_offset_in_minutes"`
	DeviceManufacturer      string     `json:"device_manufacturer"`
	DeviceOs                DeviceOS   `json:"device_os"`
	ClientType              ClientType `json:"client_type"`
	DeviceOsVersion         string     `json:"device_os_version"`
	AppVersion              string     `json:"app_version"`
	CreatedAt               time.Time  `json:"created_at"`
	UpdatedAt               time.Time  `json:"updated_at"`
	DeletedAt               *time.Time `json:"deleted_at"`
	AttachTo                *int64     `json:"attach_to"`
	LastAttachTo            *int64     `json:"last_attach_to"`
}

func NewInstallationFromDatabaseUser(i database_queries.Installation) Installation {
	deviceOs := utils.Must(new(DeviceOS).FromString(i.DeviceOs))
	clientType := utils.Must(new(ClientType).FromString(i.ClientType))

	deletedAt := new(time.Time)
	if i.DeletedAt.Valid {
		deletedAt = &i.DeletedAt.Time
	} else {
		deletedAt = nil
	}

	attachTo := new(int64)
	if i.AttachTo.Valid {
		attachTo = &i.AttachTo.Int64
	} else {
		attachTo = nil
	}

	lastAttachTo := new(int64)
	if i.LastAttachTo.Valid {
		lastAttachTo = &i.LastAttachTo.Int64
	} else {
		lastAttachTo = nil
	}

	return Installation{
		ID:                      i.ID,
		InstallationToken:       i.InstallationToken,
		NotificationToken:       i.NotificationToken.String,
		Locale:                  i.Locale,
		TimezoneOffsetInMinutes: i.TimezoneOffsetInMinutes,
		DeviceManufacturer:      i.DeviceManufacturer.String,
		DeviceOs:                *deviceOs,
		ClientType:              *clientType,
		DeviceOsVersion:         i.DeviceOsVersion.String,
		AppVersion:              i.AppVersion,
		CreatedAt:               i.CreatedAt.Time,
		UpdatedAt:               i.UpdatedAt.Time,
		DeletedAt:               deletedAt,
		AttachTo:                attachTo,
		LastAttachTo:            lastAttachTo,
	}
}

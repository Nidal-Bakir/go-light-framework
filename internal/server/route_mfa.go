package server

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"github.com/Nidal-Bakir/go-todo-backend/internal/apperr"
	"github.com/Nidal-Bakir/go-todo-backend/internal/feat/auth"
	"github.com/Nidal-Bakir/go-todo-backend/internal/middleware"
	"github.com/Nidal-Bakir/go-todo-backend/internal/tracker"
	"github.com/Nidal-Bakir/go-todo-backend/internal/utils/email"
	"github.com/Nidal-Bakir/go-todo-backend/internal/utils/phonenumber"
)

func mfaRouter(ctx context.Context, s *Server, authRepo auth.Repository) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc(
		"POST /register-otp",
		middleware.MiddlewareChain(
			mfaRegisterOtp(authRepo),
			Auth(authRepo),
		),
	)

	mux.HandleFunc(
		"POST /verify-ownership",
		middleware.MiddlewareChain(
			mfaVerifyOwnership(authRepo),
			Auth(authRepo),
		),
	)

	mux.HandleFunc(
		"GET /mfa-methods",
		middleware.MiddlewareChain(
			mfaListMfas(authRepo, false),
			Auth(authRepo),
		),
	)

	mux.HandleFunc(
		"GET /mfa-options",
		middleware.MiddlewareChain(
			mfaListMfas(authRepo, true),
			AuthForMFA(authRepo),
		),
	)

	mux.HandleFunc(
		"POST /start-pending-mfa",
		middleware.MiddlewareChain(
			mfaStartPendingMfaMethod(authRepo),
			AuthForMFA(authRepo),
		),
	)

	mux.HandleFunc(
		"POST /verify-pending-mfa",
		middleware.MiddlewareChain(
			mfaVerifyPendingOtpMfa(authRepo),
			Installation(authRepo),
			AuthForMFA(authRepo),
		),
	)

	return middleware.MiddlewareChain(
		mux.ServeHTTP,
	)
}

type mfaRegisterOtpParams struct {
	Email *email.Email
	Phone *phonenumber.PhoneNumber
}

func mfaRegisterOtp(authRepo auth.Repository) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		err := r.ParseForm()
		if err != nil {
			writeError(ctx, w, r, http.StatusBadRequest, err)
			return
		}

		params, errList := validateMfaRegisterOtpParam(r)
		if len(errList) != 0 {
			writeError(ctx, w, r, http.StatusBadRequest, errList...)
			return
		}
		userAndSession := auth.MustUserAndSessionFromContext(ctx)

		var mfaId int32
		if params.Email != nil {
			mfaId, err = authRepo.CreateEmailMfa(ctx, userAndSession.UserID, *params.Email)
		} else if params.Phone != nil {
			mfaId, err = authRepo.CreatePhoneMfa(ctx, userAndSession.UserID, *params.Phone)
		}
		if err != nil {
			writeError(ctx, w, r, return400IfAppErrOr500(err), err)
			return
		}

		response := struct {
			MfaId int32 `json:"mfa_id"`
		}{
			MfaId: mfaId,
		}
		writeResponse(ctx, w, r, http.StatusCreated, response)
	}
}

func validateMfaRegisterOtpParam(r *http.Request) (mfaRegisterOtpParams, []error) {
	params := mfaRegisterOtpParams{}
	errList := make([]error, 0, 1)

	emailStr := r.FormValue("email")
	if emailStr != "" {
		email, err := email.Parse(emailStr)
		params.Email = email
		if err != nil {
			errList = append(errList, apperr.ErrInvalidEmail)
		}
		return params, errList
	}

	phone, err := phonenumber.ParseAndValidate(assumablePhoneNumberFromRequest(r))
	if err != nil {
		errList = append(errList, apperr.ErrInvalidPhoneNumber)
	}
	params.Phone = phone
	return params, errList
}

// -----------------------------------------------------------------------------------

type mfaVerifyOwnershipParams struct {
	otp   string
	mfaId int32
}

func mfaVerifyOwnership(authRepo auth.Repository) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		err := r.ParseForm()
		if err != nil {
			writeError(ctx, w, r, http.StatusBadRequest, err)
			return
		}

		params, errList := validateMfaVerifyOwnershipParam(r)
		if len(errList) != 0 {
			writeError(ctx, w, r, http.StatusBadRequest, errList...)
			return
		}

		userAndSession := auth.MustUserAndSessionFromContext(ctx)

		err = authRepo.VerifyMfaOwnership(ctx, userAndSession.UserID, params.mfaId, params.otp)
		if err != nil {
			writeError(ctx, w, r, http.StatusBadRequest, err)
			return
		}

		apiWriteOperationDoneSuccessfullyJson(ctx, w, r)
	}
}

func validateMfaVerifyOwnershipParam(r *http.Request) (mfaVerifyOwnershipParams, []error) {
	params := mfaVerifyOwnershipParams{}
	errList := make([]error, 0, 2)

	MfaIdStr := r.FormValue("mfa_id")
	otp := r.FormValue("otp")

	mfaId, err := strconv.Atoi(MfaIdStr)
	if err != nil {
		errList = append(errList, apperr.ErrInvalidId)
	}
	if len(otp) != auth.OtpCodeLength {
		errList = append(errList, apperr.ErrInvalidOtpCode)
	}

	params.mfaId = int32(mfaId)
	params.otp = otp

	return params, errList
}

// ----------------------------------------------------------------------------------------------

type publicMfaMethods struct {
	ID                  int32  `json:"id"`
	Status              string `json:"status"`
	MethodType          string `json:"type"`
	Label               string `json:"label"`
	MethodEmailEmail    string `json:"email,omitzero"`
	MethodPhonePhone    string `json:"phone,omitzero"`
	MethodTotpAlgorithm string `json:"totp_algorithm,omitzero"`
	MethodHotpAlgorithm string `json:"hotp_algorithm,omitzero"`
}

func mfaListMfas(authRepo auth.Repository, activeOnly bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		userAndSession := auth.MustUserAndSessionFromContext(ctx)
		var list []publicMfaMethods

		if activeOnly {
			data, err := authRepo.GetAllActiveMfaMethodsForUser(ctx, int(userAndSession.UserID))
			if err != nil {
				writeError(ctx, w, r, http.StatusBadRequest, err)
				return
			}
			list = make([]publicMfaMethods, len(data))
			for i, e := range data {
				list[i] = publicMfaMethods{
					ID:                  e.ID,
					Status:              e.Status,
					MethodType:          e.MethodType,
					Label:               e.Label,
					MethodEmailEmail:    e.MethodEmailEmail.String,
					MethodPhonePhone:    e.MethodPhonePhone.String,
					MethodTotpAlgorithm: e.MethodTotpAlgorithm.String,
					MethodHotpAlgorithm: e.MethodHotpAlgorithm.String,
				}
			}
		} else {
			data, err := authRepo.GetAllMfaMethodsForUser(ctx, int(userAndSession.UserID))
			if err != nil {
				writeError(ctx, w, r, http.StatusBadRequest, err)
				return
			}
			list = make([]publicMfaMethods, len(data))
			for i, e := range data {
				list[i] = publicMfaMethods{
					ID:                  e.ID,
					Status:              e.Status,
					MethodType:          e.MethodType,
					Label:               e.Label,
					MethodEmailEmail:    e.MethodEmailEmail.String,
					MethodPhonePhone:    e.MethodPhonePhone.String,
					MethodTotpAlgorithm: e.MethodTotpAlgorithm.String,
					MethodHotpAlgorithm: e.MethodHotpAlgorithm.String,
				}
			}
		}

		writeResponse(ctx, w, r, http.StatusOK, map[string]any{"data": list})
	}
}

// _________________________________________________________________________________

func mfaStartPendingMfaMethod(authRepo auth.Repository) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		userAndSession := auth.MustUserAndSessionFromContext(ctx)

		mfaId, err := strconv.Atoi(r.FormValue("mfa_id"))
		if err != nil {
			writeError(ctx, w, r, http.StatusBadRequest, fmt.Errorf("invalid mfa_id"))
			return
		}

		err = authRepo.AddPendingMfaSession(ctx, userAndSession.SessionToken, userAndSession.UserID, int32(mfaId))
		if err != nil {
			writeError(ctx, w, r, return400IfApp404IfNoResultErrOr500(err), err)
			return
		}
		apiWriteOperationDoneSuccessfullyJson(ctx, w, r)
	}
}

// _________________________________________________________________________________

type mfaVerifyPendingOtpMfaParams struct {
	otp               string
	deviceFingerprint string
	mfaId             int32
}

func mfaVerifyPendingOtpMfa(authRepo auth.Repository) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		err := r.ParseForm()
		if err != nil {
			writeError(ctx, w, r, http.StatusBadRequest, err)
			return
		}

		params, errList := validateMfaVerifyPendingOtpMfaParam(r)
		if len(errList) != 0 {
			writeError(ctx, w, r, http.StatusBadRequest, errList...)
			return
		}

		userAndSession := auth.MustUserAndSessionFromContext(ctx)
		installation := auth.MustInstallationFromContext(ctx)
		requestIpAddres := tracker.MustReqIPFromContext(ctx)

		user, token, err := authRepo.VerifyPendingOtpMfa(ctx, params.mfaId, params.otp, userAndSession, requestIpAddres, installation, params.deviceFingerprint)
		if err != nil {
			writeError(ctx, w, r, return400IfApp404IfNoResultErrOr500(err), err)
			return
		}

		if installation.ClientType.IsWeb() {
			setAuthorizationCookie(w, token)
		}

		response := struct {
			User  *publicUser `json:"user"`
			Token string      `json:"token"`
		}{
			User:  NewPublicUserFromAuthUser(user),
			Token: token,
		}
		writeResponse(ctx, w, r, http.StatusCreated, response)
	}
}

func validateMfaVerifyPendingOtpMfaParam(r *http.Request) (mfaVerifyPendingOtpMfaParams, []error) {
	params := mfaVerifyPendingOtpMfaParams{}
	errList := make([]error, 0, 2)

	MfaIdStr := r.FormValue("mfa_id")
	otp := r.FormValue("otp")
	deviceFingerprint := r.FormValue("device_fingerprint")

	mfaId, err := strconv.Atoi(MfaIdStr)
	if err != nil {
		errList = append(errList, apperr.ErrInvalidId)
	}
	if len(otp) != auth.OtpCodeLength {
		errList = append(errList, apperr.ErrInvalidOtpCode)
	}

	params.mfaId = int32(mfaId)
	params.otp = otp
	params.deviceFingerprint = deviceFingerprint

	return params, errList
}

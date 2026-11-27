package httpserver

import (
	"errors"
	"maps"
	"net/http"
	"strings"
	"unicode/utf8"
	"uuid"

	"github.com/bootdotdev/learn-web-security/internal/accounts"
	"github.com/bootdotdev/learn-web-security/internal/auth/mfa"
	"github.com/bootdotdev/learn-web-security/internal/auth/passwordreset"
	"github.com/bootdotdev/learn-web-security/internal/auth/passwords"
	"github.com/bootdotdev/learn-web-security/internal/auth/returnto"
	"github.com/bootdotdev/learn-web-security/internal/auth/sessions"
	"github.com/bootdotdev/learn-web-security/internal/botdetection"
	"github.com/bootdotdev/learn-web-security/internal/httpx"
	"github.com/bootdotdev/learn-web-security/internal/logging"
	"github.com/bootdotdev/learn-web-security/internal/templates"
)

const (
	minimumPasswordLength = 8
)

type authPage struct {
	templates.Page
	Error    string
	ReturnTo string
}

type authHandler struct {
	accounts         *accounts.Store
	renderer         *templates.Renderer
	logger           *logging.Logger
	mfa              *mfa.Store
	passwordResets   *passwordreset.Store
	appOrigin        string
	trustedProxyHops int
}

func newAuthHandler(accountStore *accounts.Store, mfaStore *mfa.Store, passwordResetStore *passwordreset.Store, renderer *templates.Renderer, logger *logging.Logger, appOrigin string, trustedProxyHops int) *authHandler {
	return &authHandler{
		accounts:         accountStore,
		renderer:         renderer,
		logger:           logger,
		mfa:              mfaStore,
		passwordResets:   passwordResetStore,
		appOrigin:        appOrigin,
		trustedProxyHops: trustedProxyHops,
	}
}

func (handler *authHandler) LoginPage(responseWriter http.ResponseWriter, request *http.Request) {
	returnTo := safeReturnTo(strings.Join(request.URL.Query()["returnTo"], ","))
	errorMessage := ""
	if request.URL.Query().Get("verification") == "restart" {
		errorMessage = "That verification attempt is no longer valid. Log in again."
	}
	if err := handler.renderLogin(responseWriter, http.StatusOK, errorMessage, returnTo); err != nil {
		handler.internalError(responseWriter, request, err)
	}
}

func (handler *authHandler) Login(responseWriter http.ResponseWriter, request *http.Request) {
	email, err := httpx.FormValue(request, "email")
	if err != nil {
		handler.invalidForm(responseWriter)
		return
	}
	password, err := httpx.FormValue(request, "password")
	if err != nil {
		handler.invalidForm(responseWriter)
		return
	}
	returnToValue, err := httpx.FormValue(request, "returnTo")
	if err != nil {
		handler.invalidForm(responseWriter)
		return
	}
	email = accounts.NormalizeEmail(email)
	returnTo := safeReturnTo(returnToValue)

	user, found, err := handler.accounts.FindUserByEmail(request.Context(), email)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	if !found || !passwords.Verify(password, user.PasswordHash) {
		handler.logAuthenticationEvent(request, "login_attempt", map[string]any{
			"email":         email,
			"success":       false,
			"failureReason": loginFailureReason(found),
			"returnTo":      returnTo,
		})
		if err := handler.renderLogin(responseWriter, http.StatusUnauthorized, "Invalid email or password", returnTo); err != nil {
			handler.internalError(responseWriter, request, err)
		}
		return
	}

	if passwords.NeedsRehash(user.PasswordHash) {
		updatedHash, err := passwords.Hash(password)
		if err != nil {
			handler.internalError(responseWriter, request, err)
			return
		}
		err = handler.accounts.UpdatePasswordHash(request.Context(), user.ID, updatedHash)
		if err != nil {
			handler.internalError(responseWriter, request, err)
			return
		}
	}

	challengeToken := totpLoginChallengeToken(request)
	if err := handler.mfa.DeleteChallenge(request.Context(), challengeToken); err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	if user.HasTOTP {
		challenge, err := handler.mfa.CreateChallenge(request.Context(), user.ID, returnTo)
		if err != nil {
			handler.internalError(responseWriter, request, err)
			return
		}
		setTOTPLoginChallengeCookie(responseWriter, challenge)
		http.Redirect(responseWriter, request, "/login/totp", http.StatusFound)
		return
	}

	session, err := handler.accounts.CreateSession(request.Context(), user.ID)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	handler.logAuthenticationEvent(request, "login_attempt", map[string]any{
		"email":     user.Email,
		"userId":    user.ID,
		"role":      user.Role,
		"success":   true,
		"sessionId": session.Token,
		"returnTo":  returnTo,
	})
	sessions.SetCookie(responseWriter, session)
	if challengeToken != "" {
		clearTOTPLoginChallengeCookie(responseWriter)
	}
	http.Redirect(responseWriter, request, returnTo, http.StatusFound)
}

func (handler *authHandler) SignupPage(responseWriter http.ResponseWriter, request *http.Request) {
	_, current, err := sessions.Current(request, handler.accounts)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	if current {
		http.Redirect(responseWriter, request, "/account", http.StatusFound)
		return
	}
	if err := handler.renderSignup(responseWriter, http.StatusOK, ""); err != nil {
		handler.internalError(responseWriter, request, err)
	}
}

func (handler *authHandler) Signup(responseWriter http.ResponseWriter, request *http.Request) {
	bot := botdetection.ProtectSignup(responseWriter, request, handler.renderer)
	if bot {
		return
	}
	_, current, err := sessions.Current(request, handler.accounts)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	if current {
		http.Redirect(responseWriter, request, "/account", http.StatusFound)
		return
	}

	email, emailErr := httpx.FormValue(request, "email")
	displayName, displayNameErr := httpx.FormValue(request, "displayName")
	password, passwordErr := httpx.FormValue(request, "password")
	if emailErr != nil || displayNameErr != nil || passwordErr != nil {
		handler.invalidForm(responseWriter)
		return
	}
	email = accounts.NormalizeEmail(email)
	displayName = strings.TrimSpace(displayName)
	if email == "" || displayName == "" || password == "" {
		_ = handler.renderSignup(responseWriter, http.StatusBadRequest, "All fields are required")
		return
	}
	passwordLength := utf8.RuneCountInString(password)
	if passwordLength < minimumPasswordLength {
		_ = handler.renderSignup(responseWriter, http.StatusBadRequest, "Password must be at least 8 characters")
		return
	}
	if passwordLength > passwords.MaxLength {
		_ = handler.renderSignup(responseWriter, http.StatusBadRequest, "Password must not exceed 128 characters")
		return
	}

	passwordHash, err := passwords.Hash(password)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	user, err := handler.accounts.CreateCustomer(request.Context(), email, displayName, passwordHash)
	if err != nil {
		if errors.Is(err, accounts.ErrEmailExists) {
			_ = handler.renderSignup(responseWriter, http.StatusConflict, "An account already exists for that email")
			return
		}
		handler.internalError(responseWriter, request, err)
		return
	}
	session, err := handler.accounts.CreateSession(request.Context(), user.ID)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	challengeToken := totpLoginChallengeToken(request)
	if err := handler.mfa.DeleteChallenge(request.Context(), challengeToken); err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	sessions.SetCookie(responseWriter, session)
	if challengeToken != "" {
		clearTOTPLoginChallengeCookie(responseWriter)
	}
	http.Redirect(responseWriter, request, "/account", http.StatusFound)
}

func parseForm(maxBodyBytes int64, renderer *templates.Renderer) middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
			request.Body = http.MaxBytesReader(responseWriter, request.Body, maxBodyBytes)
			if err := request.ParseForm(); err != nil {
				statusCode := http.StatusBadRequest
				heading := "Invalid Request"
				message := "The submitted form is invalid."
				if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
					statusCode = http.StatusRequestEntityTooLarge
					heading = "Content Too Large"
					message = "The request body is too large."
				}
				if renderErr := httpx.RespondWithErrorPage(responseWriter, renderer, statusCode, heading, message); renderErr != nil {
					http.Error(responseWriter, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				}
				return
			}
			next.ServeHTTP(responseWriter, request)
		})
	}
}

func (handler *authHandler) Logout(responseWriter http.ResponseWriter, request *http.Request) {
	challengeToken := totpLoginChallengeToken(request)
	if err := handler.mfa.DeleteChallenge(request.Context(), challengeToken); err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	currentSession, current, err := sessions.Current(request, handler.accounts)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	if current {
		if err := handler.accounts.RevokeSession(request.Context(), currentSession.Session.Token); err != nil {
			handler.internalError(responseWriter, request, err)
			return
		}
	}
	sessions.ClearCookie(responseWriter)
	if challengeToken != "" {
		clearTOTPLoginChallengeCookie(responseWriter)
	}
	http.Redirect(responseWriter, request, "/", http.StatusFound)
}

func (handler *authHandler) renderLogin(responseWriter http.ResponseWriter, statusCode int, errorMessage, returnTo string) error {
	return handler.renderer.Render(responseWriter, statusCode, "login", authPage{
		Title:    "Log In",
		Error:    errorMessage,
		ReturnTo: returnTo,
	})
}

func (handler *authHandler) renderSignup(responseWriter http.ResponseWriter, statusCode int, errorMessage string) error {
	return handler.renderer.Render(responseWriter, statusCode, "signup", authPage{
		Title: "Create Account",
		Error: errorMessage,
	})
}

func (handler *authHandler) invalidForm(responseWriter http.ResponseWriter) {
	if err := httpx.RespondWithErrorPage(responseWriter, handler.renderer, http.StatusBadRequest, "Invalid Request", "The submitted form is invalid."); err != nil {
		http.Error(responseWriter, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

func (handler *authHandler) internalError(responseWriter http.ResponseWriter, request *http.Request, err error) {
	_ = handler.logger.Event("unhandled_error", map[string]any{
		"method":  request.Method,
		"path":    request.URL.Path,
		"message": err.Error(),
	})
	if renderErr := httpx.RespondWithErrorPage(responseWriter, handler.renderer, http.StatusInternalServerError, "Unhandled Error", err.Error()); renderErr != nil {
		http.Error(responseWriter, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

func (handler *authHandler) logAuthenticationEvent(r *http.Request, eventName string, fields map[string]any) {
	authEventMap := make(map[string]any)

	// Type assert from any to uuid.UUID so we can format it as a string.
	// If the assertion fails (ok, ignored with _, is false), we get the
	// zero UUID (00000000-...) as an acceptable fallback.
	requestId, _ := r.Context().Value(traceKey).(uuid.UUID)
	requestIdStr := requestId.String()

	sourceIp := clientIPKeyWithTrustedProxies(handler.trustedProxyHops)
	sourceIpStr := sourceIp(r)

	userId := fields["userId"]

	// If "success" is missing or isn't a bool, the assertion fails and we
	// get bool's zero value (false), so unconfirmed events log as "failure".
	outcome, _ := fields["success"].(bool)
	outcomeStr := ""
	if outcome {
		outcomeStr = "success"
	} else {
		outcomeStr = "failure"
	}

	// Copy caller fields first so our enrichment keys take precedence
	maps.Copy(authEventMap, fields)

	authEventMap["requestId"] = requestIdStr
	authEventMap["sourceIp"] = sourceIpStr
	authEventMap["userId"] = userId
	authEventMap["outcome"] = outcomeStr

	_ = handler.logger.Event(eventName, authEventMap)
}

func safeReturnTo(value string) string {
	return returnto.Safe(value)
}

func nullableUserID(user accounts.User, found bool) any {
	if !found {
		return nil
	}
	return user.ID
}

func loginFailureReason(userFound bool) string {
	if userFound {
		return "password mismatch"
	}
	return "email not found"
}

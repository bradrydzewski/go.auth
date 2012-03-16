package auth

import (
	"errors"
	"github.com/dchest/authcookie"
	"net/http"
	"net/url"
	"time"
)

// AuthConfig holds configuration parameters used when
// authenticating a user and creating a secure cookie
// user session.
type AuthConfig struct {
	CookieSecret          []byte
	CookieName            string
	CookieExp             time.Duration
	CookieMaxAge          int
	LoginRedirect         string
	LoginSuccessRedirect  string
	LogoutSuccessRedirect string
}

// Default configurations, can be set by the user
var Config = &AuthConfig{
	CookieName : "UID",
	CookieExp : time.Hour * 24 * 14,
	CookieMaxAge : 0,
	LoginRedirect : "/auth/login",
	LogoutSuccessRedirect : "/auth/login",
	LoginSuccessRedirect : "/",
}


// Secure will attempt to verify a user session exists
// prior to executing the http.Handler function. If no
// valid sessions exists, the user will be redirected
// to a login URL.
func Secure (handler http.HandlerFunc) http.HandlerFunc {
	return func (w http.ResponseWriter, r *http.Request) {
		user, err := GetAuthenticatedUser(r)

		//if no active user session then authorize user
		if user == "" || err != nil {
			http.Redirect(w, r, Config.LoginRedirect, http.StatusSeeOther)
			return
		}

		//else, add the user to the URL and continue
		r.URL.User = url.User(user)
		handler(w, r)
	}
}

// SecureAuthHandler will verify a user session exists.
// If no user sessioin exists, the user will be redirected
// to a login url. If a user session exists, the username
// will be attached to the request.
//
// This function is included primarily to simplify integration
// with the routes.go library.
// See https://github.com/bradrydzewski/routes.go
func SecureAuthHandler(w http.ResponseWriter, r *http.Request) bool {
	user, err := GetAuthenticatedUser(r)

	//if no active user session then authorize user
	if user == "" || err != nil {
		http.Redirect(w, r, Config.LoginRedirect, http.StatusSeeOther)
		return false
	}

	//else, add the user to the URL and continue
	r.URL.User = url.User(user)
	return true
}

// GetAuthenticatedUser will get the Username from the
// http session. If not active session, or if the session
// has expired, then an error will be returned.
func GetAuthenticatedUser(r *http.Request) (user string, err error) {
	//look for the authcookie
    cookie, err := r.Cookie(Config.CookieName)

	//if doesn't exist (or is malformed) redirect
	//back to the login url
	if err != nil {
		return "", err
	}

    login, expires, err := authcookie.Parse(cookie.Value, Config.CookieSecret)

	//if there was an error parsing the cookie, redirect
	//back to the login url
    if err != nil {
		return "", err
	}

	//if the cookie is expired, redirect back to the
	//login url
    if time.Now().After(expires) {
		return "", errors.New("User session Expired")
    }

	return login, nil
}

// Login will create a user's session using a secure cookie, and
// redirect back to the login url.
func LoginRedirect(w http.ResponseWriter, r *http.Request, user string) {

	// user id should not be null or blank
	if user == "" {
		return
	}

	// cookie expires in 2 weeks
    exp := time.Now().Add(Config.CookieExp)

    // generate cookie valid for 24 hours for user
    value := authcookie.New(user, exp, Config.CookieSecret)

    cookie := http.Cookie{
        Name:   Config.CookieName,
        Value:  value,
        Path:   "/",
        Domain: r.URL.Host,
    }

	// if not a session cookie
	if Config.CookieMaxAge > 0 {
		cookie.Expires = exp
		cookie.MaxAge = Config.CookieMaxAge
	}

    http.SetCookie(w, &cookie)
	http.Redirect(w, r, Config.LoginSuccessRedirect, http.StatusSeeOther)
}

// LogoutRedirect will terminate a user's session and redirect
// to a login page, and redirect back to the login url.
func LogoutRedirect(w http.ResponseWriter, r *http.Request) {
    cookie := http.Cookie{
		Name:   Config.CookieName,
		Value:  "deleted",
		Path:   "/",
		Domain: r.URL.Host,
		MaxAge: -1,
	}

    http.SetCookie(w, &cookie)
	http.Redirect(w, r, Config.LogoutSuccessRedirect, http.StatusSeeOther)
}

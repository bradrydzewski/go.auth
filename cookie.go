package auth

import (
	"errors"
	"github.com/dchest/authcookie"
	"net/http"
	"time"
)

// SetUserCookie creates a secure cookie for the given username, indicating the
// user is authenticated.
func SetUserCookie(w http.ResponseWriter, r *http.Request, user string) {

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
}

// DeleteUserCookie removes a secure cookie that was created for the user's
// login session. This effectively logs a user out of the system.
func DeleteUserCookie(w http.ResponseWriter, r *http.Request) {
	cookie := http.Cookie{
		Name:   Config.CookieName,
		Value:  "deleted",
		Path:   "/",
		Domain: r.URL.Host,
		MaxAge: -1,
	}

	http.SetCookie(w, &cookie)
}

// GetUserCookie will get the Username from the http session. If the session is
// inactive, or if the session has expired, then an error will be returned.
func GetUserCookie(r *http.Request) (user string, err error) {
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

package auth

import (
	"errors"
	"fmt"
	"github.com/dchest/authcookie"
	"net/http"
	"strings"
	"time"
)

// Error messages related to the Secure Cookie parsing and verification
var (
	ErrSessionExpired = errors.New("User session Expired")
	ErrInvalidCookieFormat= errors.New("Invalid Cookie Format")
)

// SetUserCookie creates a secure cookie for the given username, indicating the
// user is authenticated.
func SetUserCookie(w http.ResponseWriter, r *http.Request, user User) {

	cookie := &http.Cookie{
		Name:     Config.CookieName,
		Path:     "/",
		Domain:   r.URL.Host,
		HttpOnly: Config.CookieHttpOnly,
		Secure:   Config.CookieSecure,
	}

	// if not a session cookie set the MaxAge
	if Config.CookieMaxAge > 0 {
		cookie.MaxAge = Config.CookieMaxAge
	}

	SetUserCookieOpts(w, cookie, user)
}

// SetUserCookieOpts creates a secure cookie for the given User and with the
// specified cookie options.
func SetUserCookieOpts(w http.ResponseWriter, cookie *http.Cookie, user User) {

	// default cookie expiration
	exp := time.Now().Add(Config.CookieExp)

	// generate cookie valid for 24 hours for user
	// the strings are quoted to ensure they aren't tampered with
	// TODO explore storing string as a URL Parameter String
	userStr := fmt.Sprintf("%q|%q|%q|%q|%q|%q|%q",
							user.Id(), user.Provider(), user.Name(),
							user.Email(), user.Link(), user.Picture(),
							user.Org())

	// set the cookie's value
	cookie.Value = authcookie.New(userStr, exp, Config.CookieSecret)

	// set the cookie
	http.SetCookie(w, cookie)
}

// DeleteUserCookie removes a secure cookie that was created for the user's
// login session. This effectively logs a user out of the system.
func DeleteUserCookie(w http.ResponseWriter, r *http.Request) {
	DeleteUserCookieName(w, r, Config.CookieName)
}

// DeleteUserCookieName removes a secure cookie with the specified name.
func DeleteUserCookieName(w http.ResponseWriter, r *http.Request, name string) {
	cookie := http.Cookie{
		Name:   name,
		Value:  "deleted",
		Path:   "/",
		Domain: r.URL.Host,
		MaxAge: -1,
	}

	http.SetCookie(w, &cookie)
}

// GetUserCookie will get the User data from the http session. If the session is
// inactive, or if the session has expired, then an error will be returned.
func GetUserCookie(r *http.Request) (User, error) {
	return GetUserCookieName(r, Config.CookieName)
}

// GetUserCookieName will get the User data from the http session for the 
// specified secure cookie. If the session is inactive, or if the session has
// expired, then an error will be returned.
func GetUserCookieName(r *http.Request, name string) (User, error) {
	//look for the authcookie
	cookie, err := r.Cookie(name)

	//if doesn't exist (or is malformed) redirect
	//back to the login url
	if err != nil {
		return nil, err
	}

	// get the login string from authcookie
	login, expires, err := authcookie.Parse(cookie.Value, Config.CookieSecret)

	//if there was an error parsing the cookie, redirect
	//back to the login url
	if err != nil {
		return nil, err
	}

	//if the cookie is expired, redirect back to the
	//login url
	if time.Now().After(expires) {
		return nil, ErrSessionExpired
	}

	// parse the user data from the cookie string
	u := user { }
	_, err = fmt.Fscanf(strings.NewReader(login), "%q|%q|%q|%q|%q|%q|%q",
								&u.id, &u.provider, &u.name, &u.email,
								&u.link, &u.picture, &u.org)

	// if we were unable to parse the cookie return an exception
	if err != nil {
		return nil, ErrInvalidCookieFormat
	}	

	return &u, err
}

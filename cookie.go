package auth

import (
	"errors"
	"github.com/dchest/authcookie"
	"net/http"
	"strings"
	"time"
)

// SetUserCookie creates a secure cookie for the given username, indicating the
// user is authenticated.
func SetUserCookie(w http.ResponseWriter, r *http.Request, user User) {

	// cookie expires in 2 weeks
	exp := time.Now().Add(Config.CookieExp)

	// generate cookie valid for 24 hours for user
	userStr := user.Id()+"|"+user.Provider()+"|"+user.Name()+"|"+user.Email()+"|"+user.Link()+"|"+user.Picture()
	value := authcookie.New(userStr, exp, Config.CookieSecret)

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
func GetUserCookie(r *http.Request) (User, error) {
	//look for the authcookie
	cookie, err := r.Cookie(Config.CookieName)

	//if doesn't exist (or is malformed) redirect
	//back to the login url
	if err != nil {
		return nil, err
	}

	login, expires, err := authcookie.Parse(cookie.Value, Config.CookieSecret)

	//if there was an error parsing the cookie, redirect
	//back to the login url
	if err != nil {
		return nil, err
	}

	//if the cookie is expired, redirect back to the
	//login url
	if time.Now().After(expires) {
		return nil, errors.New("User session Expired")
	}

	// split the user from the provider
	s := strings.Split(login, "|")

	// the string should be split into 6 strings
	// (id, provider, name, email, link, picture)
	if len(s) != 6 {
		return nil, errors.New("Invalid Cookie Format")
	}

	u := user {
		id       : s[0],
		provider : s[1],
		name     : s[2],
		email    : s[3],
		link     : s[4],
		picture  : s[5],
	}
	return &u, nil
}

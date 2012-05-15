package auth

import (
	"net/http"
	"net/url"
)

var (
	DefaultLoginRedirect = "/auth/login"
	DefaultLoginSucessRedirect = "/"
)

// Objects implementing the AuthHandler interface can be registered to enforce
// user authentication via OAuth2, OpenID, or a custom authentication protocol.
type AuthHandler interface {
	// RedirectRequired returns a boolean value indicating if the request
	// should be redirected to the authentication provider's login screen.
	RedirectRequired(r *http.Request) bool

	// Redirect will do an http.Redirect, sending the user to the authentication
	// provider's login screen.
	Redirect(w http.ResponseWriter, r *http.Request)

	// GetAuthenticatedUser will retrieve the authenticated User from the
	// http.Request object.
	GetAuthenticatedUser(r *http.Request) (User, error)
}

// AuthMux is an HTTP request multiplexer that implements OpenID, OAuth2, and
// custom User Authentication flows. It matches the request against a list of
// registered patterns and calls the AuthHandler for the pattern that most
// closely matches the URL.
type AuthMux struct {
	handlers  map[string]AuthHandler
	success   AuthSuccess
	failure   AuthFailure
	config    *AuthConfig
}

type AuthSuccess func(w http.ResponseWriter, r *http.Request, u User)
type AuthFailure func(w http.ResponseWriter, r *http.Request, err error)

// NewAuthMux allocates and returns a new AuthMux.
func NewAuthMux(s AuthSuccess, f AuthFailure, c *AuthConfig) *AuthMux {
	mux := AuthMux{}
	mux.handlers = make(map[string]AuthHandler)
	mux.success = s
	mux.failure = f
	mux.config = c

	if c == nil { mux.config  = Config }
	if f == nil { mux.failure = mux.authFailure() }
	if s == nil { mux.success = mux.authSuccess() }

	return &mux
}

// Handle registers the AuthHandler (oauth2, openid, etc) for the given URL
// pattern. 
func (self *AuthMux) Handle(pattern string, handler AuthHandler) {
	self.handlers[pattern] = handler
}

// ServeHTTP dispatches the request to the authentication handler whose pattern
// matches the request URL.
func (self *AuthMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	// Loop through Paths to find handlers
	for path, handler := range self.handlers {
		if r.URL.Path != path {
			continue
		}

		// Redirect the user, if required
		if handler.RedirectRequired(r) == true {
			handler.Redirect(w, r)
			return
		}

		// Get the authenticated user Id
		user, err := handler.GetAuthenticatedUser(r)
		if err != nil {
			// If there was a problem, invoke failure
			self.failure(w, r, err)
			return
		}

		// Invoke the success function
		self.success(w, r, user)
	}

	// Return a NotFound if there was no provider registered
	// to match the URL Path.
	http.NotFound(w, r)
}

// SecureFunc will attempt to verify a user session exists prior to executing
// the http.Handler function. If no valid sessions exists, the user will be
// redirected to a login URL.
func (self *AuthMux) SecureFunc(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, err := GetUserCookie(r)

		//if no active user session then authorize user
		if user == "" || err != nil {
			http.Redirect(w, r, self.config.LoginRedirect, http.StatusSeeOther)
			return
		}

		//else, add the user to the URL and continue
		r.URL.User = url.User(user)
		handler(w, r)
	}
}

func (self *AuthMux) authSuccess() AuthSuccess {
	return func (w http.ResponseWriter, r *http.Request, u User) {
		SetUserCookie(w, r, u.Username())
		http.Redirect(w, r, self.config.LoginSuccessRedirect, http.StatusSeeOther)
	}
}

func (self *AuthMux) authFailure() AuthFailure {
	return func (w http.ResponseWriter, r *http.Request, err error) {
		http.Error(w, err.Error(), http.StatusForbidden)
	}
}


// DefaultAuthMux is the default AuthMux used by auth.SecureFunc and
// auth.Handle.
var DefaultAuthMux = NewAuthMux(nil, nil, nil)

// Handle registers the AuthHandler (oauth2, openid, etc) for the given URL
// pattern with the DefaultAuthMux
func Handle(pattern string, handler AuthHandler) {
	DefaultAuthMux.Handle(pattern, handler)
}

// SecureFunc will attempt to verify a user session exists prior to executing
// the http.Handler function. If no valid sessions exists, the user will be
// redirected to a login URL.
func SecureFunc(handler http.HandlerFunc) http.HandlerFunc {
	return DefaultAuthMux.SecureFunc(handler)
}

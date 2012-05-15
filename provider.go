package auth

import (
	"net/http"
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
	OnSuccess AuthSuccess
	OnFailure AuthFailure
}

type AuthSuccess func(w http.ResponseWriter, r *http.Request, u User)
type AuthFailure func(w http.ResponseWriter, r *http.Request, err error)

// NewAuthMux allocates and returns a new AuthMux.
func NewAuthMux(s AuthSuccess, f AuthFailure) *AuthMux {
	handler := AuthMux{}
	handler.handlers = make(map[string]AuthHandler)
	handler.OnSuccess = s
	handler.OnFailure = f
	return &handler
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
			// If there was a problem, invoke OnFailure
			self.OnFailure(w, r, err)
			return
		}

		// Invoke the OnSuccess function
		self.OnSuccess(w, r, user)
	}

	// Return a NotFound if there was no provider registered
	// to match the URL Path.
	http.NotFound(w, r)
}

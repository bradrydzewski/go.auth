package auth

import (
	"net/http"
)

type GoogleOpenIdHandler struct {
	OpenIdMixin
	url string
}

func NewGoogleOpenIdHandler() *GoogleOpenIdHandler {
	handler := GoogleOpenIdHandler{}
	handler.url = "https://accounts.google.com/o/openid2/auth"
	return &handler
}

// RedirectRequired 
func (self *GoogleOpenIdHandler) RedirectRequired(r *http.Request) bool {
	return r.URL.Query().Get("openid.mode") == ""
}

// Redirect will send the user to the Google OpenID Authentication URL
func (self *GoogleOpenIdHandler) Redirect(w http.ResponseWriter, r *http.Request) {
	self.OpenIdMixin.AuthorizeRedirect(w, r, self.url, nil)
}

// GetAuthenticatedUser will retrieve the User information from the URL
// query parameters, per the OpenID specification. If the authentication failed,
// the function will return an error.
func (self *GoogleOpenIdHandler) GetAuthenticatedUser(r *http.Request) (User, error) {
	return self.OpenIdMixin.GetAuthenticatedUser(r.URL.Query())
}


package auth

import (
	"net/http"
	"net/url"
)

// GoogleUser represents a Google user object returned by the OAuth2 service.
type GoogleUser struct {
	UserId      string `json:"id"`
	UserEmail   string `json:"email"`
	UserPicture string `json:"picture"`
	UserName    string `json:"name"`
	UserLink    string `json:"link"`
}

func (u *GoogleUser) Id() string       { return u.UserId }
func (u *GoogleUser) Provider() string { return "google.com" }
func (u *GoogleUser) Name() string     { return u.UserName }
func (u *GoogleUser) Email() string    { return u.UserEmail }
func (u *GoogleUser) Picture() string  { return u.UserPicture }
func (u *GoogleUser) Link() string     { return u.UserLink }
func (u *GoogleUser) Org() string      { return "" }

// GoogleProvider is an implementation of Google's Oauth2
// for web application flow.
// See https://developers.google.com/accounts/docs/OAuth2WebServer
type GoogleProvider struct {
	OAuth2Mixin
}

// NewGoogleProvider allocates and returns a new GoogleProvider.
func NewGoogleProvider(client, secret, redirect string) *GoogleProvider {
	goog := GoogleProvider{}
	goog.AuthorizationURL = "https://accounts.google.com/o/oauth2/auth"
	goog.AccessTokenURL = "https://accounts.google.com/o/oauth2/token"
	goog.RedirectURL = redirect
	goog.ClientId = client
	goog.ClientSecret = secret
	return &goog
}

// Redirect will do an http.Redirect, sending the user to the Google login
// screen.
func (self *GoogleProvider) Redirect(w http.ResponseWriter, r *http.Request) {
	const scope = "https://www.googleapis.com/auth/userinfo.profile+https://www.googleapis.com/auth/userinfo.email"
	self.OAuth2Mixin.AuthorizeRedirect(w, r, scope)
}

// GetAuthenticatedUser will retrieve the Authentication User from the
// http.Request object.
func (self *GoogleProvider) GetAuthenticatedUser(w http.ResponseWriter, r *http.Request) (User, Token, error) {
	// Get the OAuth2 Access Token
	token, err := self.GetAccessToken(r)
	if err != nil {
		return nil, nil, err
	}

	user := GoogleUser{}
	params := url.Values{}
	params.Add("access_token", token.AccessToken)
	err = self.OAuth2Mixin.GetAuthenticatedUser("https://www.googleapis.com/oauth2/v2/userinfo", params, &user)
	return &user, token, err
}

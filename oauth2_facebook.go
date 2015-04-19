package auth

import (
	"net/http"
	"net/url"
)

type FacebookPicture struct {
	URL string `json:"url"`
}

// FacebookUser represents a Facebook user object returned by the OAuth2 service.
type FacebookUser struct {
	UserId      string                         `json:"id"`
	UserEmail   string                         `json:"email"`
	UserPicture struct{ Data FacebookPicture } `json:"picture"`
	UserName    string                         `json:"name"`
	UserLink    string                         `json:"link"`
}

func (u *FacebookUser) Id() string       { return u.UserId }
func (u *FacebookUser) Provider() string { return "facebook.com" }
func (u *FacebookUser) Name() string     { return u.UserName }
func (u *FacebookUser) Email() string    { return u.UserEmail }
func (u *FacebookUser) Picture() string  { return u.UserPicture.Data.URL }
func (u *FacebookUser) Link() string     { return u.UserLink }
func (u *FacebookUser) Org() string      { return "" }

// FacebookProvider is an implementation of Facebook's Oauth2
// for web application flow.
// See https://developers.facebook.com/docs/facebook-login/manually-build-a-login-flow/v2.3
type FacebookProvider struct {
	OAuth2Mixin
	Scope string
}

// NewFacebookProvider allocates and returns a new FacebookProvider.
func NewFacebookProvider(client, secret, redirect string) *FacebookProvider {
	fb := FacebookProvider{}
	fb.Client.UseGetForTokenRequests = true
	fb.AuthorizationURL = "https://www.facebook.com/dialog/oauth"
	fb.AccessTokenURL = "https://graph.facebook.com/v2.3/oauth/access_token"
	fb.RedirectURL = redirect
	fb.ClientId = client
	fb.ClientSecret = secret
	return &fb
}

// Redirect will do an http.Redirect, sending the user to the Facebook login
// screen.
func (self *FacebookProvider) Redirect(w http.ResponseWriter, r *http.Request) {
	const scope = "public_profile"
	self.OAuth2Mixin.AuthorizeRedirect(w, r, scope)
}

// GetAuthenticatedUser will retrieve the Authentication User from the
// http.Request object.
func (self *FacebookProvider) GetAuthenticatedUser(w http.ResponseWriter, r *http.Request) (User, Token, error) {
	// Get the OAuth2 Access Token
	token, err := self.GetAccessToken(r)
	if err != nil {
		return nil, nil, err
	}

	user := FacebookUser{}
	params := url.Values{}
	params.Add("access_token", token.AccessToken)
	params.Add("fields", "id,name,picture")
	err = self.OAuth2Mixin.GetAuthenticatedUser("https://graph.facebook.com/v2.3/me", params, &user)
	return &user, token, err
}

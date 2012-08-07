package auth

import (
	"encoding/json"
	"errors"
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

	AuthorizeUrl      string
	AccessTokenUrl    string
	UserResourceUrl   string
	UserResourceScope string
}

// NewGoogleProvider allocates and returns a new GoogleProvider.
func NewGoogleProvider(client, secret, redirect string) *GoogleProvider {
	goog := GoogleProvider{}
	goog.AuthorizeUrl = "https://accounts.google.com/o/oauth2/auth"
	goog.AccessTokenUrl = "https://accounts.google.com/o/oauth2/token"
	goog.UserResourceUrl = "https://www.googleapis.com/oauth2/v2/userinfo"
	goog.UserResourceScope = "https://www.googleapis.com/auth/userinfo.profile+https://www.googleapis.com/auth/userinfo.email"
	goog.ClientId = client
	goog.ClientSecret = secret
	goog.RedirectUrl = redirect
	return &goog
}

// RedirectRequired returns a boolean value indicating if the request should
// be redirected to the Google login screen, in order to provide an OAuth
// Access Token.
func (self *GoogleProvider) RedirectRequired(r *http.Request) bool {
	return r.URL.Query().Get("code") == ""
}

// Redirect will do an http.Redirect, sending the user to the Google login
// screen.
func (self *GoogleProvider) Redirect(w http.ResponseWriter, r *http.Request) {
	params := make(url.Values)
	params.Add("response_type", "code")
	params.Add("scope", self.UserResourceScope)
	params.Add("access_type", "offline")

	self.OAuth2Mixin.AuthorizeRedirect(w, r, self.AuthorizeUrl, params)
}

// GetAuthenticatedUser will retrieve the Authentication User from the
// http.Request object.
func (self *GoogleProvider) GetAuthenticatedUser(r *http.Request) (User, error) {
	// Get the OAuth2 Access Token
	token, err := self.GetAccessToken(r)
	if err != nil {
		return nil, err
	}

	// Use the Access Token to retrieve the user's information
	header := make(http.Header)
	header.Add("Authorization", "OAuth "+token)

	user := GoogleUser{}
	err = self.OAuth2Mixin.GetAuthenticatedUser(self.UserResourceUrl, token, header, &user)
	return &user, err
}

// GetAccessToken will retrieve the Access Token from the http.Request URL.
func (self *GoogleProvider) GetAccessToken(r *http.Request) (string, error) {

	code := r.URL.Query().Get("code")
	if code == "" {
		return "", errors.New("No Access Code in the Request URL")
	}

	params := make(url.Values)
	params.Add("code", code)
	params.Add("scope", "")
	params.Add("grant_type", "authorization_code")

	header := make(http.Header)
	header.Add("Content-Type", "application/x-www-form-urlencoded")

	tokenStr, err := self.OAuth2Mixin.GetAccessToken(self.AccessTokenUrl, params, header)
	if err != nil {
		return "", err
	}

	token := GoogleTokenResp{}
	err = json.Unmarshal([]byte(tokenStr), &token)
	if err != nil {
		return "", err
	}

	return token.AccessToken, nil
}

// GoogleTokenResp represents the response data type returned from an Access
// Token request
type GoogleTokenResp struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int32  `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

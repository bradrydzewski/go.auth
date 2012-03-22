package auth

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
)

// GoogleUser represents a Google user
// object returned by the Oauth service.
type GoogleUser struct {
	Id      string `json:"id"`
	Email   string `json:"email"`
	Picture string `json:"picture"`
	Name    string `json:"name"`
	Link    string `json:"link"`
}

func (u *GoogleUser) Username() string {
	return u.Link
}

func (u *GoogleUser) Password() string {
	return ""
}

func (u *GoogleUser) Fullname() string {
	return u.Name
}

func (u *GoogleUser) Icon() string {
	return u.Picture
}

func (u *GoogleUser) Url() string {
	return u.Link
}

// GoogleHandler is an implementation of Google's Oauth2 
// for web application flow.
// See https://developers.google.com/accounts/docs/OAuth2WebServer
type GoogleHandler struct {
	OAuth2Mixin

	AuthorizeUrl      string
	AccessTokenUrl    string
	UserResourceUrl   string
	UserResourceScope string
}

func NewGoogleHandler(clientId, clientSecret, redirectUrl string) *GoogleHandler {
	goog := GoogleHandler{}
	goog.AuthorizeUrl = "https://accounts.google.com/o/oauth2/auth"
	goog.AccessTokenUrl = "https://accounts.google.com/o/oauth2/token"
	goog.UserResourceUrl = "https://www.googleapis.com/oauth2/v1/userinfo"
	goog.UserResourceScope = "https://www.googleapis.com/auth/userinfo.profile"
	goog.ClientId = clientId
	goog.ClientSecret = clientSecret
	goog.RedirectUrl = redirectUrl
	return &goog
}

func (self *GoogleHandler) GetAuthenticatedUser(accessToken string) (User, error) {

	header := make(http.Header)
	header.Add("Authorization", "OAuth "+accessToken)

	user := &GoogleUser{}
	err := self.OAuth2Mixin.GetAuthenticatedUser(self.UserResourceUrl, accessToken, header, user)
	return user, err
}

func (self *GoogleHandler) AuthorizeRedirect(w http.ResponseWriter, r *http.Request) {
	params := make(url.Values)
	params.Add("response_type", "code")
	params.Add("scope", self.UserResourceScope)
	params.Add("access_type", "offline")

	self.OAuth2Mixin.AuthorizeRedirect(w, r, self.AuthorizeUrl, params)
}

func (self *GoogleHandler) GetAccessToken(r *http.Request) (string, error) {

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

// GoogleTokenResp represents the response data type
// returned from an Access Token request
type GoogleTokenResp struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int32  `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

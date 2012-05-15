package auth

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
)

// GitHubUser represents a GitHub user object returned by the OAuth2 service.
type GitHubUser struct {
	Id     int64  `json:"id"`
	Email  string `json:"email"`
	Avatar string `json:"avatar_url"`
	Name   string `json:"name"`
	Login  string `json:"login"`
	Link   string `json:"url"`
}

func (u *GitHubUser) Userid() string {
	return strconv.FormatInt(int64(u.Id), 10)
}

func (u *GitHubUser) Username() string {
	return u.Login
}

func (u *GitHubUser) Password() string {
	return ""
}

func (u *GitHubUser) EmailAddr() string {
	return u.Email
}

func (u *GitHubUser) Fullname() string {
	return u.Name
}

func (u *GitHubUser) Icon() string {
	return u.Avatar
}

func (u *GitHubUser) Url() string {
	return u.Link
}

func (u *GitHubUser) Provider() string {
	return "github.com"
}

// GitHubHandler is an implementation of Github's Oauth2 protocol.
// See http://developer.github.com/v3/oauth/
type GitHubHandler struct {
	OAuth2Mixin

	AuthorizeUrl    string
	AccessTokenUrl  string
	UserResourceUrl string
}

// NewGitHubHandler creates a new GitHubHandler.
func NewGitHubHandler(clientId, clientSecret string) *GitHubHandler {
	gitHub := GitHubHandler{}
	gitHub.AuthorizeUrl = "https://github.com/login/oauth/authorize"
	gitHub.AccessTokenUrl = "https://github.com/login/oauth/access_token"
	gitHub.UserResourceUrl = "https://api.github.com/user"
	gitHub.ClientId = clientId
	gitHub.ClientSecret = clientSecret

	return &gitHub
}

// RedirectRequired returns a boolean value indicating if the request should
// be redirected to the Github login screen, in order to provide an OAuth
// Access Token.
func (self *GitHubHandler) RedirectRequired(r *http.Request) bool {
	return r.URL.Query().Get("code") == ""
}

// Redirect will do an http.Redirect, sending the user to the Github login
// screen.
func (self *GitHubHandler) Redirect(w http.ResponseWriter, r *http.Request) {
	params := make(url.Values)
	params.Add("scope", "users")
	self.OAuth2Mixin.AuthorizeRedirect(w, r, self.AuthorizeUrl, params)
}

// GetAuthenticatedUser will retrieve the Authentication User from the
// http.Request object.
func (self *GitHubHandler) GetAuthenticatedUser(r *http.Request) (User, error) {
	// Get the OAuth2 Access Token
	token, err := self.GetAccessToken(r)
	if err != nil {
		return nil, err
	}

	// Use the Access Token to retrieve the user's information
	user := GitHubUser{}
	err = self.OAuth2Mixin.GetAuthenticatedUser(self.UserResourceUrl, token, nil, &user)
	return &user, err
}

// GetAccessToken will retrieve the Access Token from the http.Request URL.
func (self *GitHubHandler) GetAccessToken(r *http.Request) (string, error) {

	code := r.URL.Query().Get("code")
	if code == "" {
		return "", errors.New("No Access Code in the Request URL")
	}

	params := make(url.Values)
	params.Add("scope", "users")
	params.Add("code", code)

	return self.OAuth2Mixin.GetAccessToken(self.AccessTokenUrl, params, nil)
}

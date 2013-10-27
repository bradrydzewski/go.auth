package auth

import (
	"net/http"
)

type GitHubUser struct {
	UserEmail    interface{} `json:"email"`
	UserName     interface{} `json:"name"`
	UserGravatar interface{} `json:"gravatar_id"`
	UserCompany  interface{} `json:"company"`
	UserLink     interface{} `json:"html_url"`
	UserLogin    string      `json:"login"`
}

func (u *GitHubUser) Id() string       { return u.UserLogin }
func (u *GitHubUser) Provider() string { return "github.com" }

// Below fields need to be parsed as interface{} and converted to String
// because Golang (as of version 1.0) does not support parsing JSON Strings
// with an explicit null value.

func (u *GitHubUser) Name() string {
	if u.UserName == nil {
		return ""
	}
	return u.UserName.(string)
}

func (u *GitHubUser) Email() string {
	if u.UserEmail == nil {
		return ""
	}
	return u.UserEmail.(string)
}

func (u *GitHubUser) Link() string {
	if u.UserLink == nil {
		return ""
	}
	return u.UserLink.(string)
}

func (u *GitHubUser) Picture() string {
	if u.UserGravatar == nil {
		return ""
	}
	// use the Gravatar Id instead of the Avatar URL, which has a bunch
	// of un-necessary data (as far as I can tell) appended to the end.
	return "https://secure.gravatar.com/avatar/" + u.UserGravatar.(string)
}

func (u *GitHubUser) Org() string {
	if u.UserCompany == nil {
		return ""
	}
	return u.UserCompany.(string)
}

// GithubProvider is an implementation of Github's Oauth2 protocol.
// See http://developer.github.com/v3/oauth/
type GithubProvider struct {
	OAuth2Mixin
	Scope string
}

// NewGithubProvider allocates and returns a new GithubProvider.
func NewGithubProvider(clientId, clientSecret, scope string) *GithubProvider {
	github := GithubProvider{}
	github.AuthorizationURL = "https://github.com/login/oauth/authorize"
	github.AccessTokenURL = "https://github.com/login/oauth/access_token"
	github.ClientId = clientId
	github.ClientSecret = clientSecret
	github.Scope = scope

	// default the Scope if not provided
	if len(github.Scope) == 0 {
		github.Scope = "user:email"
	}
	return &github
}

// Redirect will do an http.Redirect, sending the user to the Github login
// screen.
func (self *GithubProvider) Redirect(w http.ResponseWriter, r *http.Request) {
	self.OAuth2Mixin.AuthorizeRedirect(w, r, self.Scope)
}

// GetAuthenticatedUser will retrieve the Authentication User from the
// http.Request object.
func (self *GithubProvider) GetAuthenticatedUser(w http.ResponseWriter, r *http.Request) (User, Token, error) {

	// Get the OAuth2 Access Token
	token, err := self.GetAccessToken(r)
	if err != nil {
		return nil, nil, err
	}

	user := GitHubUser{}
	err = self.OAuth2Mixin.GetAuthenticatedUser("https://api.github.com/user", token.AccessToken, &user)
	return &user, token, err
}

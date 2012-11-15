package auth

import (
	"errors"
	"net/http"
	"net/url"
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
	if u.UserName == nil { return "" }; 
	return u.UserName.(string)
}

func (u *GitHubUser) Email() string {
	if u.UserEmail == nil { return "" }
	return u.UserEmail.(string)
}

func (u *GitHubUser) Link() string {
	if u.UserLink == nil { return "" }
	return u.UserLink.(string)
}

func (u *GitHubUser) Picture() string {
	if u.UserGravatar == nil { return "" }
	// use the Gravatar Id instead of the Avatar URL, which has a bunch
	// of un-necessary data (as far as I can tell) appended to the end.
	return "https://secure.gravatar.com/avatar/" + u.UserGravatar.(string)
}

func (u *GitHubUser) Org() string {
	if u.UserCompany == nil { return "" }
	return u.UserCompany.(string)
}


// GithubProvider is an implementation of Github's Oauth2 protocol.
// See http://developer.github.com/v3/oauth/
type GithubProvider struct {
	OAuth2Mixin

	AuthorizeUrl    string
	AccessTokenUrl  string
	UserResourceUrl string
}

// NewGithubProvider allocates and returns a new GithubProvider.
func NewGithubProvider(clientId, clientSecret string) *GithubProvider {
	github := GithubProvider{}
	github.AuthorizeUrl = "https://github.com/login/oauth/authorize"
	github.AccessTokenUrl = "https://github.com/login/oauth/access_token"
	github.UserResourceUrl = "https://api.github.com/user"
	github.ClientId = clientId
	github.ClientSecret = clientSecret
	return &github
}

// Redirect will do an http.Redirect, sending the user to the Github login
// screen.
func (self *GithubProvider) Redirect(w http.ResponseWriter, r *http.Request) {
	params := make(url.Values)
	params.Add("scope", "users")
	self.OAuth2Mixin.AuthorizeRedirect(w, r, self.AuthorizeUrl, params)
}

// GetAuthenticatedUser will retrieve the Authentication User from the
// http.Request object.
func (self *GithubProvider) GetAuthenticatedUser(r *http.Request) (User, error) {
	// Get the OAuth2 Access Token
	token, err := self.GetAccessToken(r)
	if err != nil {
		return nil, err
	}

println("Token:", token)
println("ClientId:", self.ClientId)
println("ClientSecret:", self.ClientSecret)


 
	// Use the Access Token to retrieve the user's information
	user := GitHubUser{}
	err = self.OAuth2Mixin.GetAuthenticatedUser(self.UserResourceUrl, token, nil, &user)
	return &user, err
}

// GetAccessToken will retrieve the Access Token from the http.Request URL.
func (self *GithubProvider) GetAccessToken(r *http.Request) (string, error) {

	code := r.URL.Query().Get("code")
	if code == "" {
		return "", errors.New("No Access Code in the Request URL")
	}

	params := make(url.Values)
	params.Add("scope", "users")
	params.Add("code", code)

	return self.OAuth2Mixin.GetAccessToken(self.AccessTokenUrl, params, nil)
}

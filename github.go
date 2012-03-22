package auth

import(
	"errors"
	"net/http"
	"net/url"
)


// GitHubUser represents a GitHub user
// object returned by the Oauth service.
type GitHubUser struct {
    Email   string `json:"email"`
    Avatar  string `json:"avatar_url"`
    Name    string `json:"name"`
    Login   string `json:"login"`
    Link    string `json:"url"`
}

func (u *GitHubUser) Username() string { 
	return u.Link
}

func (u *GitHubUser) Password() string { 
	return ""
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

// GetAuthenticatedUser will use the Github User API to retrieve
// user data for the given access token.
func (self *GitHubHandler) GetAuthenticatedUser(accessToken string) (User, error) {
	user := GitHubUser{}
	err := self.OAuth2Mixin.GetAuthenticatedUser(self.UserResourceUrl, accessToken, nil, &user)
	return &user, err
}

// AuthorizeRedirect will redirect the user to the Github
// login screen for authorization.
func (self *GitHubHandler) AuthorizeRedirect(w http.ResponseWriter, r *http.Request) {
	params := make(url.Values)
	params.Add("scope", "users")
	self.OAuth2Mixin.AuthorizeRedirect(w, r, self.AuthorizeUrl, params)
}

// GetAccessToken will request an Access Token from Github
// using an access code in the Request URL.
func (self *GitHubHandler) GetAccessToken(r *http.Request) (string, error) {

	code := r.URL.Query().Get("code");
	if code == "" {
		return "", errors.New("No Access Code in the Request URL")
	}

	params := make(url.Values)
	params.Add("scope", "users")
	params.Add("code", code)
	
	return self.OAuth2Mixin.GetAccessToken(self.AccessTokenUrl, params, nil)
}

/*
func (self *GitHubHandler) HandlerFunc() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// attempt to get the access token
		token, err := self.GetAccessToken(r)
		if err != nil {
			//if user not authorized, redirect
			self.AuthorizeRedirect(w, r)
			return
		}

		// get the authorized user
		user, err := self.GetAuthenticatedUser(token)

		if err != nil {
			//if we can't get the user data, display an error message
			http.Error(w, "", http.StatusForbidden)
			return
		}

		// else, set the secure user cookie
		SetUserCookie(w, r, user.Username())

		// redirect the user now that they are logged in
		http.Redirect(w, r, Config.LoginSuccessRedirect, http.StatusSeeOther)
	}
}
*/

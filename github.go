package auth

import(
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
)

const (
	GithubAuthUrl  = "https://github.com/login/oauth/authorize"
	GithubTokenUrl = "https://github.com/login/oauth/access_token"
	GithubUserUrl  = "https://api.github.com/user"
)

// GitHubAuth is an implementation of Github's Oauth2 protocol.
// See http://developer.github.com/v3/oauth/
type GitHubAuth struct {
	ClientId     string
	ClientSecret string
}

// GitHubUser represents a GitHub user
// object returned by the Oauth service.
type GitHubUser struct {
    Email   string `json:"email"`
    Avatar  string `json:"avatar_url"`
    Name    string `json:"name"`
    Login   string `json:"login"`
    Link    string `json:"url"`
}

func NewGitHubAuth(clientId, clientSecret string) *GitHubAuth {
	githubAuth := GitHubAuth{}
	githubAuth.ClientId = clientId
	githubAuth.ClientSecret = clientSecret
	return &githubAuth
}

func (this *GitHubAuth) Authorize(w http.ResponseWriter, r *http.Request) {

	params := r.URL.Query()

	if code := params.Get("code"); code != "" {
		//get the access token
		accessToken, err := this.GetAccessToken(code)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		//get the github user data
		user, err := this.GetAuthenticatedUser(accessToken)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}    

		//authorize the user
		LoginRedirect(w, r, user.Link)
		return
	}

	//send to the github login
	this.AuthorizeRedirect(w, r)
}

// Sends a user to the Github Login page.
func (this *GitHubAuth) AuthorizeRedirect(w http.ResponseWriter, r *http.Request) {

	// create github login url params
	loginParams := make(url.Values)
	//loginParams.Add("redirect_uri", redirectUrl.String())
	loginParams.Add("client_id", this.ClientId)
	loginParams.Add("scope", "users")

	// create github url
	loginUrl, _ := url.Parse(GithubAuthUrl)
	loginUrl.RawQuery = loginParams.Encode()

	// redirect to Github
	http.Redirect(w, r, loginUrl.String(), http.StatusSeeOther)
}

// Retrieves an Access token using the provided access code.
func (this *GitHubAuth) GetAccessToken(code string) (string, error) {
	//First we need to get an Oauth access token
	//create the access url params
	accessParams := make(url.Values)
	accessParams.Add("client_id", this.ClientId)
	accessParams.Add("client_secret", this.ClientSecret)
	accessParams.Add("code", code)

	//create the access url
	GithubAuthUrl, _ := url.Parse(GithubTokenUrl)
	GithubAuthUrl.RawQuery = accessParams.Encode()

	//create the http request
	req := http.Request{
		URL:        GithubAuthUrl,
		Method:     "POST",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Close:      true,
	}

	//do the http request and get the response
	resp, err := http.DefaultClient.Do(&req)
	if err != nil {
		return "", err
	}

	//get the response body
	accessToken, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()

	if err != nil {
		return "", err
	}

	return string(accessToken), nil
}

// Retrieves the Github User data for the given access token.
func (this *GitHubAuth) GetAuthenticatedUser(accessToken string) (*GitHubUser, error) {

	//create the user url
	GithubUserUrl, _ := url.Parse(GithubUserUrl)
	GithubUserUrl.RawQuery = accessToken

	//create the http request for the user Url
	req := http.Request{
		URL:        GithubUserUrl,
		Method:     "GET",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Close:      true,
	}

	//do the http request and get the response
	resp, err := http.DefaultClient.Do(&req)
	if err != nil {
		return nil, err
	}

	//get the response body
	userData, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		return nil, err
	}

	//unmarshal user json
    gitHubUser := GitHubUser{}
	json.Unmarshal(userData, &gitHubUser)
	return &gitHubUser, nil
}

package auth

import(
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

const (
	GoogAuthUrl = "https://accounts.google.com/o/oauth2/auth"
	GoogTokenUrl = "https://accounts.google.com/o/oauth2/token"
	GoogUserUrl = "https://www.googleapis.com/oauth2/v1/userinfo"
	GoogScope = "https://www.googleapis.com/auth/userinfo.profile"
)

// GoogleOAuth is an implementation of Google's Oauth2 
// for web application flow.
// See https://developers.google.com/accounts/docs/OAuth2WebServer
type GoogleOAuth struct {
	ClientId     string
	ClientSecret string
	RedirectUrl  string
}

type GoogleTokenResp struct {
    AccessToken string `json:"access_token"`
    ExpiresIn   int32  `json:"expires_in"`
    TokenType   string `json:"token_type"`
}

// GoogleUser represents a Google user
// object returned by the Oauth service.
type GoogleUser struct {
	Id        string `json:"id"`
    Email     string `json:"email"`
    Picture   string `json:"picture"`
    Name      string `json:"name"`
    Link      string `json:"link"`
}

func NewGoogleOAuth(clientId, clientSecret, redirectUrl string) *GoogleOAuth {
	googleOAuth := GoogleOAuth{}
	googleOAuth.ClientId = clientId
	googleOAuth.ClientSecret = clientSecret
	googleOAuth.RedirectUrl = redirectUrl
	return &googleOAuth
}

func (this *GoogleOAuth) Authorize(w http.ResponseWriter, r *http.Request) {

	params := r.URL.Query()

	if code := params.Get("code"); code != "" {

		//get the access token
		accessToken, err := this.GetAccessToken(code)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		//get the google user data
		user, err := this.GetAuthenticatedUser(accessToken)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}    

		//authorize the user
		LoginRedirect(w, r, user.Link)
		return

	} else if err := params.Get("error"); err != "" {
		http.Error(w, err, http.StatusUnauthorized)
		return
	}

	//send to the google login
	this.AuthorizeRedirect(w, r)
}

// Sends a user to the Google Login page.
// TODO this code is *almost* identical to Github
func (this *GoogleOAuth) AuthorizeRedirect(w http.ResponseWriter, r *http.Request) {

	// create google login url params
	loginParams := make(url.Values)
	loginParams.Add("client_id", this.ClientId)
	loginParams.Add("response_type", "code")
	loginParams.Add("scope", GoogScope)
	loginParams.Add("redirect_uri", this.RedirectUrl)
	loginParams.Add("access_type", "offline")

	// create google url
	loginUrl, _ := url.Parse(GoogAuthUrl)
	loginUrl.RawQuery = loginParams.Encode()

	// redirect to Google login screen
	http.Redirect(w, r, loginUrl.String(), http.StatusSeeOther)
}

// Retrieves an Access token using the provided access code.
func (this *GoogleOAuth) GetAccessToken(code string) (string, error) {

	//First we need to get an Oauth access token
	//create the access url params
	accessParams := make(url.Values)
	accessParams.Add("code", code)
	accessParams.Add("redirect_uri", this.RedirectUrl)
	accessParams.Add("client_id", this.ClientId)
	accessParams.Add("scope", "")
	accessParams.Add("client_secret", this.ClientSecret)
	accessParams.Add("grant_type", "authorization_code")

	//create the access url
	GoogAuthUrl, _ := url.Parse(GoogTokenUrl)

	//create the http request
	req := http.Request{
		URL:        GoogAuthUrl,
		Method:     "POST",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Close:      true,
	}

	//add url parameters to the body?
	reader := strings.NewReader(accessParams.Encode())
	req.Body = ioutil.NopCloser(reader)

	req.Header = make(http.Header)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

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

	googTokenResp := GoogleTokenResp{}
	json.Unmarshal(accessToken, &googTokenResp)
	return googTokenResp.AccessToken, nil
}

// Retrieves the Google User data for the given access token.
// TODO this code is *almost* identical to Github, except we pass the oauth token in a header instead of url param
func (this *GoogleOAuth) GetAuthenticatedUser(accessToken string) (*GoogleUser, error) {

	//create the user url
	GoogUserUrl, _ := url.Parse(GoogUserUrl)

	//create the http request for the user Url
	req := http.Request{
		URL:        GoogUserUrl,
		Method:     "GET",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Close:      true,
	}

	//add the access token to the header
	req.Header = make(http.Header)
	req.Header.Add("Authorization", "OAuth " + accessToken)

	//do the http request and get the response
	//TODO: handler error response code
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
    googleUser := GoogleUser{}
	json.Unmarshal(userData, &googleUser)
	return &googleUser, nil
}

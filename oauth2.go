package auth

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/bradrydzewski/go.auth/oauth2"
)

// Abstract implementation of OAuth2 for user authentication.
type OAuth2Mixin struct {
	oauth2.Client
}

// RedirectRequired returns a boolean value indicating if the request should
// be redirected to the Provider's login screen, in order to provide an OAuth
// Access Token.
func (self *OAuth2Mixin) RedirectRequired(r *http.Request) bool {
	return r.URL.Query().Get("code") == ""
}

// Redirects the User to the Login Screen
func (self *OAuth2Mixin) AuthorizeRedirect(w http.ResponseWriter, r *http.Request, scope string) {
	url := self.Client.AuthorizeRedirect(scope, "")
	http.Redirect(w, r, url, http.StatusSeeOther)
}

// Exchanges the verifier for an OAuth2 Access Token.
func (self *OAuth2Mixin) GetAccessToken(r *http.Request) (*oauth2.Token, error) {

	code := r.URL.Query().Get("code")
	if len(code) == 0 {
		return nil, errors.New("No Access Code in the Request URL")
	}

	accessToken, err := self.Client.GrantToken(code)
	if err != nil {
		return nil, err
	}

	return accessToken, err
}

// Gets the Authenticated User
func (self *OAuth2Mixin) GetAuthenticatedUser(endpoint string, accessToken string, resp interface{}) error {

	//create the user url
	endpointUrl, _ := url.Parse(endpoint)
	endpointUrl.RawQuery = "access_token="+accessToken

	//create the http request for the user Url
	req := http.Request{
		URL:        endpointUrl,
		Method:     "GET",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Close:      true,
	}

	//do the http request and get the response
	r, err := http.DefaultClient.Do(&req)
	if err != nil {
		return err
	}

	//get the response body
	userData, err := ioutil.ReadAll(r.Body)
	defer r.Body.Close()
	if err != nil {
		return err
	}

	//unmarshal user json
	return json.Unmarshal(userData, &resp)
}

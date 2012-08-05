package auth

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

// Abstract implementation of OAuth2 for user authentication.
type OAuth2Mixin struct {
	ClientId     string
	ClientSecret string
	RedirectUrl  string
}

// RedirectRequired returns a boolean value indicating if the request should
// be redirected to the Provider's login screen, in order to provide an OAuth
// Access Token.
func (self *OAuth2Mixin) RedirectRequired(r *http.Request) bool {
	return r.URL.Query().Get("code") == ""
}

func (self *OAuth2Mixin) GetAccessToken(endpoint string, params url.Values,
	headers http.Header) (string, error) {

	//create the access token url params
	if params == nil {
		params = make(url.Values)
	}

	//add the client id, client secret and code to the query params
	params.Add("client_id", self.ClientId)
	params.Add("client_secret", self.ClientSecret)
	if self.RedirectUrl != "" {
		params.Add("redirect_uri", self.RedirectUrl)
	}

	//create the access token request url
	accessTokenUrl, _ := url.Parse(endpoint)
	accessTokenUrl.RawQuery = params.Encode()

	//create the http request
	req := http.Request{
		URL:        accessTokenUrl,
		Method:     "POST",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Close:      true,
	}

	//set the header variables
	req.Header = headers

	//HACK for Google implementation
	//need to find a better way to handle this
	if headers != nil {
		req.URL.RawQuery = ""
		reader := strings.NewReader(params.Encode())
		req.Body = ioutil.NopCloser(reader)
	}

	//do the http request and get the response
	response, err := http.DefaultClient.Do(&req)
	if err != nil {
		return "", err
	}

	//get the response body
	accessToken, err := ioutil.ReadAll(response.Body)
	defer response.Body.Close()

	if err != nil {
		return "", err
	}

	return string(accessToken), nil
}

func (self *OAuth2Mixin) AuthorizeRedirect(w http.ResponseWriter, r *http.Request,
	endpoint string, params url.Values) {

	if params == nil {
		params = make(url.Values)
	}
	params.Add("client_id", self.ClientId)
	if self.RedirectUrl != "" {
		params.Add("redirect_uri", self.RedirectUrl)
	}

	// create auth url
	loginUrl, _ := url.Parse(endpoint)
	loginUrl.RawQuery = params.Encode()

	//HACK encode() with encode the "+" that separates the scopes
	//we will do a find / replace to change this
	loginUrl.RawQuery = strings.Replace(loginUrl.RawQuery, "%2B", "+", -1)

	// redirect to login
	http.Redirect(w, r, loginUrl.String(), http.StatusSeeOther)
}

func (self *OAuth2Mixin) GetAuthenticatedUser(endpoint string, accessToken string,
	headers http.Header, resp interface{}) error {

	//create the user url
	endpointUrl, _ := url.Parse(endpoint)
	endpointUrl.RawQuery = accessToken

	//create the http request for the user Url
	req := http.Request{
		URL:        endpointUrl,
		Method:     "GET",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Close:      true,
	}

	//add request headers
	req.Header = headers

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

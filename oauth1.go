package auth

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/bradrydzewski/go.auth/oauth1"
)

// Abstract implementation of OAuth2 for user authentication.
type OAuth1Mixin struct {
	oauth1.Consumer
}

// Redirect will do an http.Redirect, sending the user to the Provider's
// login screen.
func (self *OAuth1Mixin) Redirect(w http.ResponseWriter, r *http.Request) {
	if err := self.AuthorizeRedirect(w, r, self.Consumer.AuthorizationURL); err != nil {
		println("Error redirecting to authorization endpoint: " + err.Error())
	}
}

// RedirectRequired returns a boolean value indicating if the request should
// be redirected to the Provider's login screen, in order to provide an OAuth
// Verifier Token.
func (self *OAuth1Mixin) RedirectRequired(r *http.Request) bool {
	return r.URL.Query().Get("oauth_verifier") == ""
}

// Redirects the User to the OAuth1.0a provider's Login Screen. A RequestToken
// is requested from the Provider, and included in the URL's oauth_token param.
//
// A Successful Login / Authorization should return both the oauth_token and
// the oauth_verifier to the callback URL.
func (self *OAuth1Mixin) AuthorizeRedirect(w http.ResponseWriter, r *http.Request, endpoint string) error {

	//Get a Request Token
	token, err := self.Consumer.RequestToken()
	if err != nil {
		return err
	}

	//Get the redirect URL
	url, err := self.Consumer.AuthorizeRedirect(token)
	if err != nil {
		return err
	}

	//Write the Request Token to a Cookie, so that we can
	//retrieve it after re-directing the user to the
	//providers authorization screen.
	cookie := http.Cookie{}
	cookie.Name = "_token"
	cookie.Path = "/"
	cookie.Domain = r.URL.Host
	cookie.HttpOnly = true
	cookie.Secure = Config.CookieSecure
	cookie.Value = token.Encode()
	http.SetCookie(w, &cookie)

	// redirect to the login url
	http.Redirect(w, r, url, http.StatusSeeOther)
	return nil
}

// AuthorizeToken trades the Verification Code (oauth_verification) for an
// Access Token.
func (self *OAuth1Mixin) AuthorizeToken(w http.ResponseWriter, r *http.Request) (*oauth1.AccessToken, error) {

	//Get the presisted request token
	cookie, err := r.Cookie("_token")
	if err != nil {
		return nil, nil
	}

	//Parse the persisted request token
	requestToken, err := oauth1.ParseRequestTokenStr(cookie.Value)
	if err != nil {
		return nil, err
	}

	//Delete the request Token ...don't need it anymore
	DeleteUserCookieName(w,r,"_token")

	//Parse the verification code from the Redirect URL
	verifier := r.URL.Query().Get("oauth_verifier")

	//Upgrade to an Authorization Token
	accessToken, err := self.Consumer.AuthorizeToken(requestToken, verifier)
	if err != nil {
		return nil, err
	}

	return accessToken, nil
}

func (self *OAuth1Mixin) GetAuthenticatedUser(endpoint string, token *oauth1.AccessToken, resp interface{}) error {

	//create the user url
	endpointUrl, _ := url.Parse(endpoint)

	//create the http request for the user Url
	req := http.Request{
		URL:        endpointUrl,
		Method:     "GET",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Close:      true,
	}

	//sign the request with the access token
	self.Sign(&req, token)

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


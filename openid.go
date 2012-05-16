package auth

import (
	"errors"
	"net/http"
	"net/url"
)

const (
	GoogleOpenIdEndpoint = "https://accounts.google.com/o/openid2/auth"
)

var (
	ErrAuthDeclined = errors.New("Login was unsuccessful or cancelled by User")
)

var openIdParams = map[string]string{
	"openid.ns":                "http://specs.openid.net/auth/2.0",
	"openid.ns.ax":             "http://openid.net/srv/ax/1.0",
	"openid.mode":              "checkid_setup",
	"openid.ax.mode":           "fetch_request",
	"openid.ax.required":       "firstname,lastname,username,language,email",
	"openid.ax.type.username":  "http://axschema.org/namePerson/friendly",
	"openid.ax.type.language":  "http://axschema.org/pref/language",
	"openid.ax.type.fullname":  "http://axschema.org/namePerson",
	"openid.ax.type.lastname":  "http://axschema.org/namePerson/last",
	"openid.ax.type.firstname": "http://axschema.org/namePerson/first",
	"openid.ax.type.email":     "http://axschema.org/contact/email",
	"openid.claimed_id":        "http://specs.openid.net/auth/2.0/identifier_select",
	"openid.identity":          "http://specs.openid.net/auth/2.0/identifier_select",
}

// Base implementation of OpenID for user authentication.
type OpenIdProvider struct {
	endpoint string
}

// NewOpenIdProvider allocates and returns a new OpenIdProvider.
func NewOpenIdProvider(endpoint string) *OpenIdProvider {
	return &OpenIdProvider{ endpoint }
}

func (self *OpenIdProvider) RedirectRequired(r *http.Request) bool {
	return r.URL.Query().Get("openid.mode") == ""
}

// Redirect will send the user to the OpenId Authentication URL
func (self *OpenIdProvider) Redirect(w http.ResponseWriter, r *http.Request) {

	// create the url params
	var params = make(url.Values)

	// construct the Redirect URL with default OpenId params
	for key, val := range openIdParams {
		params.Add(key, val)
	}

	// append the real and return_to parameters
	// they will be defaulted to the current Host / Path
	// TODO use url.New().String() instead string joins below
	params.Add("openid.realm", "http://"+r.Host)
	params.Add("openid.return_to", "http://"+r.Host+r.URL.Path)

	// create the redirect url
	redirectTo, _ := url.Parse(self.endpoint)
	redirectTo.RawQuery = params.Encode()

	// redirect to login
	http.Redirect(w, r, redirectTo.String(), http.StatusSeeOther)
}

// GetAuthenticatedUser will retrieve the User information from the URL
// query parameters, per the OpenID specification. If the authentication failed,
// the function will return an error.
func (self *OpenIdProvider) GetAuthenticatedUser(r *http.Request) (User, error) {

	// Parse the url parameters
	params := r.URL.Query()

	// Check to see if the user successfully authenticated
	if params.Get("openid.mode") == "cancel" {
		return nil, ErrAuthDeclined
	}

	// Get the user details from the URL parameters
	lastName := params.Get("openid.ext1.value.lastname")
	firstName := params.Get("openid.ext1.value.firstname")
	fullName := firstName + " " + lastName
	email := params.Get("openid.ext1.value.email")

	// Return the User data
	// TODO for now we are re-using the Google User
	user := GoogleUser{Id: email, Email: email, Name: fullName}
	return &user, nil
}

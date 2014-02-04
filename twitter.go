package auth

import (
	"net/http"
)

type TwitterUser struct {
	UserId string `json:"screen_name"`
}

func (u *TwitterUser) Id()       string { return u.UserId }
func (u *TwitterUser) Provider() string { return "twitter.com" }
func (u *TwitterUser) Name()     string { return u.UserId }
func (u *TwitterUser) Email()    string { return "" }
func (u *TwitterUser) Link()     string { return "https://www.twitter.com/" + u.UserId }
func (u *TwitterUser) Picture()  string { return "" }
func (u *TwitterUser) Org()      string { return "" }


// TwitterProvider is an implementation of Twitters's Oauth1.0a protocol.
// See https://dev.twitter.com/docs/auth/implementing-sign-twitter
type TwitterProvider struct {
	OAuth1Mixin
}

// NewTwitterProvider allocates and returns a new TwitterProvider.
func NewTwitterProvider(key, secret, callback string) *TwitterProvider {
	twitter := TwitterProvider{}
	twitter.AuthorizationURL = "https://api.twitter.com/oauth/authorize"
	twitter.RequestTokenURL = "https://api.twitter.com/oauth/request_token"
	twitter.AccessTokenURL =  "https://api.twitter.com/oauth/access_token"

	twitter.CallbackURL = callback
	twitter.ConsumerKey = key
	twitter.ConsumerSecret = secret
	return &twitter
}

// GetAuthenticatedUser will upgrade the oauth_token to an access token, and
// invoke the appropriate Twitter REST API call to get the User's information.
func (self *TwitterProvider) GetAuthenticatedUser(w http.ResponseWriter, r *http.Request) (User, Token, error) {

	// upgrade the oauth_token to an access token
	token, err := self.OAuth1Mixin.AuthorizeToken(w, r)
	if err != nil {
		return nil, nil, err
	}

	// get the Bitbucket User details
	user := TwitterUser{}
	if err := self.OAuth1Mixin.GetAuthenticatedUser("https://api.twitter.com/1.1/account/settings.json", token, &user); err != nil {
		return nil, nil, err
	}
	return &user, token, err
}

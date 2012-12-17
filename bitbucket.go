package auth

import (
	"net/http"
)

type BitbucketUser struct {
	UserId        string `json:"username"`
	UserPicture   string `json:"avatar"`
	UserLastName  string `json:"last_name"`
	UserFirstName string `json:"first_name"`
}

func (u *BitbucketUser) Id()       string { return u.UserId }
func (u *BitbucketUser) Provider() string { return "bitbucket.org" }
func (u *BitbucketUser) Name()     string { return u.UserId }
func (u *BitbucketUser) Email()    string { return "" }
func (u *BitbucketUser) Link()     string { return "https://bitbucket.org/"+u.UserId }
func (u *BitbucketUser) Picture()  string { return u.UserPicture }
func (u *BitbucketUser) Org()      string { return "" }


// BitbucketProvider is an implementation of Bitbucket's Oauth1.0a protocol.
// See https://confluence.atlassian.com/display/BITBUCKET/OAuth+on+Bitbucket
type BitbucketProvider struct {
	OAuth1Mixin
}

// NewBitbucketProvider allocates and returns a new BitbucketProvider.
func NewBitbucketProvider(key, secret, callback string) *BitbucketProvider {
	bb := BitbucketProvider{}
	bb.AuthorizationURL = "https://bitbucket.org/!api/1.0/oauth/authenticate"
	bb.RequestTokenURL = "https://bitbucket.org/api/1.0/oauth/request_token/"
	bb.AccessTokenURL = "https://bitbucket.org/api/1.0/oauth/access_token/"

	bb.CallbackURL = callback
	bb.ConsumerKey = key
	bb.ConsumerSecret = secret
	return &bb
}

// GetAuthenticatedUser will upgrade the oauth_token to an access token, and
// invoke the appropriate Bitbucket REST API call to get the User's information.
func (self *BitbucketProvider) GetAuthenticatedUser(w http.ResponseWriter, r *http.Request) (User, Token, error) {

	// upgrade the oauth_token to an access token
	token, err := self.OAuth1Mixin.AuthorizeToken(w, r)
	if err != nil {
		return nil, nil, err
	}

	// bitbuckets user object comes wrapped in a composite object.
	wrapper := struct {
		User *BitbucketUser `json:"user"`
	}{}

	// get the Bitbucket User details
	if err := self.OAuth1Mixin.GetAuthenticatedUser("https://api.bitbucket.org/1.0/user", token, &wrapper); err != nil {
		return nil, nil, err
	}

	if wrapper.User == nil {
		//TODO throw an exception
	}

	return wrapper.User, token, nil
	
}

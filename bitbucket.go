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
func (u *BitbucketUser) Provider() string { return "bitbucket.com" }
func (u *BitbucketUser) Name()     string { return u.UserId }
func (u *BitbucketUser) Email()    string { return "" }
func (u *BitbucketUser) Link()     string { return "https://bitbucket.org/"+u.UserId }
func (u *BitbucketUser) Picture()  string { return u.UserPicture }
func (u *BitbucketUser) Org()      string { return "" }


// BitbucketProvider is an implementation of Bitbucket's Oauth1.0a protocol.
// See https://confluence.atlassian.com/display/BITBUCKET/OAuth+on+Bitbucket
type BitbucketProvider struct {
	OAuth1Mixin
	UserResourceUrl string
}

// NewBitbucketProvider allocates and returns a new BitbucketProvider.
func NewBitbucketProvider(key, secret, callback string) *BitbucketProvider {
	bb := BitbucketProvider{}
	bb.AuthorizeUrl = "https://bitbucket.org/!api/1.0/oauth/authenticate"
	bb.RequestToken = "https://bitbucket.org/api/1.0/oauth/request_token/"
	bb.AccessToken = "https://bitbucket.org/api/1.0/oauth/access_token/"
	bb.UserResourceUrl = "https://api.bitbucket.org/1.0/user"

	bb.CallbackUrl = callback
	bb.ConsumerKey = key
	bb.ConsumerSecret = secret
	return &bb
}

// Redirect will do an http.Redirect, sending the user to the Bitbucket login
// screen.
func (self *BitbucketProvider) Redirect(w http.ResponseWriter, r *http.Request) {
	//params := make(url.Values)
	//params.Add("scope", "users,repo")
	self.OAuth1Mixin.AuthorizeRedirect(w, r, self.AuthorizeUrl)
}

// GetAuthenticatedUser will upgrade the oauth_token to an access token, and
// invoke the appropriate Bitbucket REST API call to get the User's information.
func (self *BitbucketProvider) GetAuthenticatedUser(r *http.Request) (User, error) {

	// upgrade the oauth_token to an access token
	token, secret, err := self.OAuth1Mixin.AuthorizeToken(r)
	if err != nil {
		return nil, err
	}

	// bitbuckets user object comes wrapped in a composite object.
	wrapper := struct {
		User *BitbucketUser `json:"user"`
	}{}

	// get the Bitbucket User details
	if err := self.OAuth1Mixin.GetAuthenticatedUser(self.UserResourceUrl, token, secret, &wrapper); err != nil {
		return nil, err
	}

	if wrapper.User == nil {
		//TODO throw an exception
	}

	return wrapper.User, nil
	
}

package auth

import (
	"net/http"
	//"net/url"
)


// TwitterProvider is an implementation of Twitter's OAuth 1.0a protocol.
// See https://dev.twitter.com/docs/auth/implementing-sign-twitter
type TwitterProvider struct {
	ConsumerKey    string
	ConsumerSecret string
	CallbackUrl    string
}

// NewTwitterProvider allocates and returns a new TwitterProvider.
func NewTwitterProvider(key, secret, callback string) *TwitterProvider {
	return &TwitterProvider{ 
		ConsumerKey : key,
		ConsumerSecret : secret,
		CallbackUrl : callback,
	}
}

func (self *TwitterProvider) RedirectRequired(r *http.Request) bool {
	return r.URL.Query().Get("oauth_token") != ""
}

// Redirect will send the user to Twitter's Login URL
func (self *TwitterProvider) Redirect(w http.ResponseWriter, r *http.Request) {

}

func (self *TwitterProvider) GetAuthenticatedUser(r *http.Request) (User, error) {
	// Parse Request token from http.Request
	// Do an http Post to convert the request token to an access token, parse the username
	return nil, nil
}

type TwitterUser struct {
	
}

/*

Step 1: Obtaining a request token
-------------------------------------------

REQUEST -----------------------------------

POST /oauth/request_token HTTP/1.1
User-Agent: themattharris' HTTP Client
Host: api.twitter.com
Authorization: 
        OAuth oauth_callback="http%3A%2F%2Flocalhost%2Fsign-in-with-twitter%2F",
              oauth_consumer_key="cChZNFj6T5R0TigYB9yd1w",
              oauth_nonce="ea9ec8429b68d6b77cd5600adbbb0456",
              oauth_signature="F1Li3tvehgcraF8DMJ7OyxO4w9Y%3D",
              oauth_signature_method="HMAC-SHA1",
              oauth_timestamp="1318467427",
              oauth_version="1.0"

RESPONSE ------------------------------------

HTTP/1.1 200 OK
Date: Thu, 13 Oct 2011 00:57:06 GMT
Status: 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 146
Pragma: no-cache
Expires: Tue, 31 Mar 1981 05:00:00 GMT
Cache-Control: no-cache, no-store, must-revalidate, pre-check=0, post-check=0
Vary: Accept-Encoding
Server: tfe

oauth_token=NPcudxy0yU5T3tBzho7iCotZ3cnetKwcTIRlX0iwRl0&
oauth_token_secret=veNRnAWe6inFuo8o2u8SLLZLjolYDmDP7SzL0YfYI&
oauth_callback_confirmed=true



Step 2: Redirecting the user
----------------------------------------------

REQUEST --------------------------------------

https://api.twitter.com/oauth/authenticate?oauth_token=NPcudxy0yU5T3tBzho7iCotZ3cnetKwcTIRlX0iwRl0


RESPONSE -------------------------------------

GET /sign-in-with-twitter/?
        oauth_token=NPcudxy0yU5T3tBzho7iCotZ3cnetKwcTIRlX0iwRl0&
        oauth_verifier=uw7NjWHT6OJ1MpJOXsHfNxoAhPKpgI8BlYDhxEjIBY HTTP/1.1
Host: localhost
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/535.5 (KHTML, like Gecko) Chrome/16.0.891.1 Safari/535.5
Accept: text/html,application/xhtml+xml,application/xml;q=0.9;q=0.8
Referer: http://localhost/sign-in-with-twitter/
Accept-Encoding: gzip,deflate,sdch
Accept-Language: en-US,en;q=0.8
Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.3



Step 3: Converting the request token to an access token
----------------------------------------------

REQUEST --------------------------------------

POST /oauth/access_token HTTP/1.1
User-Agent: themattharris' HTTP Client
Host: api.twitter.com
Authorization: OAuth oauth_consumer_key="cChZNFj6T5R0TigYB9yd1w",
                     oauth_nonce="a9900fe68e2573b27a37f10fbad6a755",
                     oauth_signature="39cipBtIOHEEnybAR4sATQTpl2I%3D",
                     oauth_signature_method="HMAC-SHA1",
                     oauth_timestamp="1318467427",
                     oauth_token="NPcudxy0yU5T3tBzho7iCotZ3cnetKwcTIRlX0iwRl0",
                     oauth_version="1.0"
Content-Length: 57
Content-Type: application/x-www-form-urlencoded

oauth_verifier=uw7NjWHT6OJ1MpJOXsHfNxoAhPKpgI8BlYDhxEjIBY


RESPONSE -------------------------------------

HTTP/1.1 200 OK
Date: Thu, 13 Oct 2011 00:57:08 GMT
Status: 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 157
Pragma: no-cache
Expires: Tue, 31 Mar 1981 05:00:00 GMT
Cache-Control: no-cache, no-store, must-revalidate, pre-check=0, post-check=0
Vary: Accept-Encoding
Server: tfe

oauth_token=7588892-kagSNqWge8gB1WwE3plnFsJHAZVfxWD7Vb57p0b4&
oauth_token_secret=PbKfYqSryyeKDWz4ebtY3o5ogNLG11WJuZBc9fQrQo


NOTE:
A successful response contains the oauth_token, oauth_token_secret, user_id, and screen_name parameters.
The token and token secret should be stored and used for future authenticated requests to the Twitter API.

*/

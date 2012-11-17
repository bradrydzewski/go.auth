package auth

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	//"strings"
	"time"

	"code.google.com/p/vitess/go/cache"
)

// Abstract implementation of OAuth2 for user authentication.
type OAuth1Mixin struct {
	AuthorizeUrl    string
	RequestToken    string
	AccessToken     string
	CallbackUrl     string

	ConsumerKey     string
	ConsumerSecret  string
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

	//create the http request to fetch a Request Token.
	requestTokenUrl, _ := url.Parse(self.RequestToken)
	req := http.Request{
		URL:        requestTokenUrl,
		Method:     "GET",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Close:      true,
	}

	//set the header variables (using defualts), and add the callback URL
	headers := headers(self.ConsumerKey)
	headers["oauth_callback"] = self.CallbackUrl
	
	//sign the request ...
	key := url.QueryEscape(self.ConsumerSecret) + "&" + url.QueryEscape("")
	base := requestString(req.Method, req.URL.String(), headers)
	headers["oauth_signature"] = sign(base, key)

	//add the Authorization header to the request
	req.Header = http.Header{}
	req.Header.Add("Authorization", authorizationString(headers))

	//make the http request and get the response
	resp, err := http.DefaultClient.Do(&req)
	if err != nil {
		return err
	}

	//parse the oauth_token and oauth_token_secret from the body
	t, err := parseToken(resp.Body)
	if err != nil {
		return err
	}

	//add the request token to the cache, where the oauth_token is the key.
	//we do this because we will need to reference the request token's
	//oauth_token_secret after the user has authentication, and upgrade to
	//an access token.
	tokenCache.Set(t.Token, t)

	// construct the login URL
	params := make(url.Values)
	params.Add("oauth_token", t.Token)

	loginUrl, _ := url.Parse(endpoint)
	loginUrl.RawQuery = params.Encode()

	// redirect to the login url
	http.Redirect(w, r, loginUrl.String(), http.StatusSeeOther)
	return nil
}

// AuthorizeToken trades the Verification Code (oauth_verification) for an
// Access Token.
func (self *OAuth1Mixin) AuthorizeToken(r *http.Request) (string, string, error) {

	//create the http request to fetch a Request Token.
	accessTokenUrl, _ := url.Parse(self.AccessToken)
	req := http.Request{
		URL:        accessTokenUrl,
		Method:     "GET",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Close:      true,
	}

	//parse oauth data from Redirect URL
	queryParams := r.URL.Query()
	oauthToken := queryParams.Get("oauth_token")
	verifier := queryParams.Get("oauth_verifier")

	//get the secret token from the session cache
	cachedSecretToken, ok := tokenCache.Get(oauthToken)
	if !ok {
		//TODO throw some kind of exception
	}

	//set the header variables (using defualts), and add the callback URL
	headers := headers(self.ConsumerKey)
	headers["oauth_token"] = oauthToken
	headers["oauth_verifier"] = verifier

	//sign the request ...
	key := url.QueryEscape(self.ConsumerSecret) + "&" + url.QueryEscape(cachedSecretToken.(*token).Secret)
	base := requestString(req.Method, req.URL.String(), headers)
	headers["oauth_signature"] = sign(base, key)

	//add the Authorization header to the request
	req.Header = http.Header{}
	req.Header.Add("Authorization", authorizationString(headers))
	//req.Header.Add("Content-Type","application/x-www-form-urlencoded")
	//req.Header.Add("Content-Length",strconv.Itoa(len(verifierString)))
	//req.Body = ioutil.NopCloser(strings.NewReader(verifierString))

	//make the http request and get the response
	resp, err := http.DefaultClient.Do(&req)
	if err != nil {
		return "","", err
	}

	//get the request body
	t, err := parseToken(resp.Body)
	if err != nil {
		return "", "", err
	}

	return t.Token, t.Secret, nil
}

func (self *OAuth1Mixin) GetAuthenticatedUser(endpoint, token, secret string, resp interface{}) error {

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

	//set the header variables (using defualts), and add the callback URL
	headers := headers(self.ConsumerKey)
	headers["oauth_token"] = token

	//sign the request ...
	key := url.QueryEscape(self.ConsumerSecret) + "&" + url.QueryEscape(secret)
	base := requestString(req.Method, req.URL.String(), headers)
	headers["oauth_signature"] = sign(base, key)

	//add the Authorization header to the request
	req.Header = http.Header{}
	req.Header.Add("Authorization", authorizationString(headers))

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


// Token & Cache ---------------------------------------------------------------

// cache used to store the oauth_token_secret between sessions. By default it
// stores 1MB of data. When the limit is reached the cache will clear out older
// items (which by the time they are removed from the cache should not be
// needed anymore). 
var tokenCache = cache.NewLRUCache(1048576) 

// token represents a Request Token or Access Token
type token struct {
	Token  string // the oauth_token value
	Secret string // the oauth_token_secret value
}

// Parses a Token from the stream (typically a http.Request Body).
func parseToken(reader io.ReadCloser) (*token, error)  {
	body, err := ioutil.ReadAll(reader)
	reader.Close()
	if err != nil {
		return nil, err
	}

	//parse the request token from the body
	bodyStr := string(body)
	parts, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, err
	}

	t := token{}
	t.Token = parts.Get("oauth_token")
	t.Secret = parts.Get("oauth_token_secret")

	switch {
	case len(t.Token) == 0  : return nil, errors.New(bodyStr)
	case len(t.Secret) == 0 : return nil, errors.New(bodyStr)
	}

	return &t, nil
}

// Gets the size (in bytes) of the Token. This is used to implement the
// cache.Value interface, allowing this struct to be stored in the LRUCache.
func (t token) Size() int {
	return len(t.Token) + len(t.Secret)
}


// Helper Functions ------------------------------------------------------------

// Gets the default set of OAuth1.0a headers.
func headers(consumerKey string) map[string]string {
	return map[string]string{
		"oauth_consumer_key"     : consumerKey,
		"oauth_nonce"            : strconv.FormatInt(nonce(), 10),
		"oauth_signature_method" : "HMAC-SHA1",
		"oauth_timestamp"        : strconv.FormatInt(now(), 10),
		"oauth_version"          : "1.0",
	}
}

// Generates a nonce value using the random package and the
// current Unix time.
func nonce() int64 {
	return rand.New(rand.NewSource(now())).Int63()
}

// Gets the current time
func now() int64 {
	return time.Now().Unix()
	//return time.Now().UTC().Unix()
}

// Generates an HMAC Signature for an OAuth1.0a request.
func sign(message, key string) string {
	hashfun := hmac.New(sha1.New, []byte(key))
	hashfun.Write([]byte(message))
	rawsignature := hashfun.Sum(nil)
	base64signature := make([]byte, base64.StdEncoding.EncodedLen(len(rawsignature)))
	base64.StdEncoding.Encode(base64signature, rawsignature)
	return string(base64signature)
}




func requestString(method string, uri string, params map[string]string) string {
	
	// loop through params, add keys to map
	var keys []string
	for key, _ := range params {
		keys = append(keys, key)
	}

	// sort the array of header keys
	sort.StringSlice(keys).Sort()

	// create the signed string
	result := method + "&" + url.QueryEscape(uri)

	// loop through sorted params and append to the string
	for pos, key := range keys {
		if pos == 0 {
			result += "&"
		} else {
			result += url.QueryEscape("&")
		}
		result += url.QueryEscape(fmt.Sprintf("%s=%s", key, url.QueryEscape(params[key])))
	}

	return result
}

func authorizationString(params map[string]string) string {
	
	// loop through params, add keys to map
	var keys []string
	for key, _ := range params {
		keys = append(keys, key)
	}

	// sort the array of header keys
	sort.StringSlice(keys).Sort()

	// create the signed string
	var str string

	// loop through sorted params and append to the string
	for i, key := range keys {
		if i > 0 { str += "," }
		str += fmt.Sprintf("%s=%q", key, url.QueryEscape(params[key]))//key + "=\"" + params[key] + "\""
	}

	return fmt.Sprintf("OAuth %s", str)
}

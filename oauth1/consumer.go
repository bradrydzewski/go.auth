package oauth1

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"time"
)

// Out-Of-Band mode, used for applications that do not have
// a callback URL, such as mobile phones or command-line
// utilities.
const OOB = "oob"

// Consumer represents a website or application that uses the
// OAuth 1.0a protocol to access protected resources on behalf
// of a User.
type Consumer struct {
	// A value used by the Consumer to identify itself
	// to the Service Provider.
	ConsumerKey string

	// A secret used by the Consumer to establish
	// ownership of the Consumer Key.
	ConsumerSecret string

	// An absolute URL to which the Service Provider will redirect
	// the User back when the Obtaining User Authorization step
	// is completed.
	//
	// If the Consumer is unable to receive callbacks or a callback
	// URL has been established via other means, the parameter
	// value MUST be set to oob (case sensitive), to indicate
	// an out-of-band configuration.
	CallbackURL string

	// The URL used to obtain an unauthorized
	// Request Token.
	RequestTokenURL string

	// The URL used to obtain User authorization
	// for Consumer access.
	AccessTokenURL string

	// The URL used to exchange the User-authorized
	// Request Token for an Access Token.
	AuthorizationURL string
}

func (c *Consumer) RequestToken() (*RequestToken, error) {

	// create the http request to fetch a Request Token.
	requestTokenUrl, _ := url.Parse(c.RequestTokenURL)
	req := http.Request{
		URL:        requestTokenUrl,
		Method:     "GET",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Close:      true,
	}

	// sign the request
	err := c.SignParams(&req, nil, map[string]string{ "oauth_callback":c.CallbackURL })
	if err != nil {
		return nil, err
	}

	// make the http request and get the response
	resp, err := http.DefaultClient.Do(&req)
	if err != nil {
		return nil, err
	}

	// parse the Request's Body
	requestToken, err := ParseRequestToken(resp.Body)
	if err != nil {
		return nil, err
	}

	return requestToken, nil
}

// AuthorizeRedirect constructs the request URL that should be used
// to redirect the User to verify User identify and consent.
func (c *Consumer) AuthorizeRedirect(t *RequestToken) (string, error) {
	redirect, err := url.Parse(c.AuthorizationURL)
	if err != nil {
		return "", err
	}
	params := make(url.Values)
	params.Add("oauth_token", t.token)
	redirect.RawQuery = params.Encode()
	return redirect.String(), nil
}

func (c *Consumer) AuthorizeToken(t *RequestToken, verifier string) (*AccessToken, error) {

	// create the http request to fetch a Request Token.
	accessTokenUrl, _ := url.Parse(c.AccessTokenURL)
	req := http.Request{
		URL:        accessTokenUrl,
		Method:     "POST",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Close:      true,
	}

	// sign the request
	err := c.SignParams(&req, t, map[string]string{ "oauth_verifier":verifier })
	if err != nil {
		return nil, err
	}

	// make the http request and get the response
	resp, err := http.DefaultClient.Do(&req)
	if err != nil {
		return nil, err
	}

	// parse the Request's Body
	accessToken, err := ParseAccessToken(resp.Body)
	if err != nil {
		return nil, err
	}

	return accessToken, nil
}

// Sign will sign an http.Request using the provided token.
func (c *Consumer) Sign(req *http.Request, token Token) error {
	return c.SignParams(req, token, nil)
}

// Sign will sign an http.Request using the provided token, and additional
// parameters.
func (c *Consumer) SignParams(req *http.Request, token Token, params map[string]string) error {

	// ensure the parameter map is not nil
	if params == nil {
		params = map[string]string{}
	}

	// ensure default parameters are set
	//params["oauth_token"]            = token.Token()
	params["oauth_consumer_key"]     = c.ConsumerKey
	params["oauth_nonce"]            = nonce()
	params["oauth_signature_method"] = "HMAC-SHA1"
	params["oauth_timestamp"]        = timestamp()
	params["oauth_version"]          = "1.0"

	var tokenSecret string
	if token != nil {
		tokenSecret = token.Secret()
		params["oauth_token"] = token.Token()
	}

	// create the oauth signature
	key := url.QueryEscape(c.ConsumerSecret) + "&" + url.QueryEscape(tokenSecret)
	base := requestString(req.Method, req.URL.String(), params)
	params["oauth_signature"] = sign(base, key)

	// ensure the http.Request's Header is not nil
	if req.Header == nil {
		req.Header = http.Header{}
	}
	
	// add the authorization header string
	req.Header.Add("Authorization", authorizationString(params))

	// ensure the appropriate content-type is set for POST
	if req.Method == "POST" {
		req.Header.Set("Content-Type","application/x-www-form-urlencoded")
	}

	return nil
}

// -----------------------------------------------------------------------------
// Private Helper Functions

// Nonce generates a random string. Nonce's are uniquely generated
// for each request.
func nonce() string {
	return strconv.FormatInt(
			rand.New(rand.NewSource(time.Now().Unix())).Int63(), 10)
}

// Timestamp generates a timestamp, expressed in the number of seconds
// since January 1, 1970 00:00:00 GMT.
func timestamp() string {
	return strconv.FormatInt(time.Now().Unix(), 10)
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

// Gets the default set of OAuth1.0a headers.
func headers(consumerKey string) map[string]string {
	return map[string]string{
		"oauth_consumer_key"     : consumerKey,
		"oauth_nonce"            : nonce(),
		"oauth_signature_method" : "HMAC-SHA1",
		"oauth_timestamp"        : timestamp(),
		"oauth_version"          : "1.0",
	}
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


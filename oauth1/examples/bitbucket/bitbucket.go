package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/bradrydzewski/go.auth/oauth1"
)

var consumer = oauth1.Consumer {
	RequestTokenURL  : "https://bitbucket.org/api/1.0/oauth/request_token/",
	AuthorizationURL : "https://bitbucket.org/!api/1.0/oauth/authenticate",
	AccessTokenURL   : "https://bitbucket.org/api/1.0/oauth/access_token/",
	CallbackURL      : oauth1.OOB,
}

func main() {

	// You must provide the Consumer Key and Consumer Secret as input args
	flag.StringVar(&consumer.ConsumerKey, "consumer_key", "", "Consumer Key from https://bitbucket.org")
	flag.StringVar(&consumer.ConsumerSecret, "consumer_secret", "", "Consumer Secret from https://bitbucket.org")
	flag.Parse()

	// If Consumer Key or Consumer Secret were not provided, exit
	if len(consumer.ConsumerKey) == 0 || len(consumer.ConsumerSecret) == 0 {
		flag.PrintDefaults()
		return
	}

	// Generate a Request Token
	requestToken, err := consumer.RequestToken()
	if err != nil {
		log.Fatal(err)
	}

	// Generate an Authorization URL (we'll direct the user here)
	url, err := consumer.AuthorizeRedirect(requestToken)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("(1) Go to: " + url)
	fmt.Println("(2) Grant access, you should get back a verification code.")
	fmt.Println("(3) Enter that verification code here: ")

	// get verification code entered by user
	var verifier string
	fmt.Scanln(&verifier)

	// authorize the token with the specified verification code
	accessToken, err := consumer.AuthorizeToken(requestToken, verifier)
	if err != nil {
		log.Fatal(err)
	}

	// create the http.Request that will access a restricted resource
	req, _ := http.NewRequest("GET", "https://api.bitbucket.org/1.0/user/repositories/dashboard", nil)
		
	// sign the request
	if err := consumer.Sign(req, accessToken); err != nil {
		log.Fatal(err)
	}

	// make the request
	resp, err := http.DefaultClient.Do(req)
	defer resp.Body.Close()
	if err != nil {
		log.Fatal(err)
	}

	bits, err := ioutil.ReadAll(resp.Body)
	fmt.Println("Got Data:\n" + string(bits))
}

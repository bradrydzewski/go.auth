package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/bradrydzewski/go.auth/oauth2"
)

type User struct {
	Login string `json:"login"`
}

var client = oauth2.Client{
	RedirectURL:      "https://github.com/litl/rauth/",
	AccessTokenURL:   "https://github.com/login/oauth/access_token",
	AuthorizationURL: "https://github.com/login/oauth/authorize",
}

func main() {

	// You must provide the ClientId and ClientSecret as input args
	flag.StringVar(&client.ClientId, "client_id", "", "Client Id from https://github.com/settings/applications")
	flag.StringVar(&client.ClientSecret, "client_secret", "", "Client Secret from https://github.com/settings/applications")
	flag.Parse()

	// If ClientId or ClientSecret were not provided, exit
	if len(client.ClientId) == 0 || len(client.ClientSecret) == 0 {
		flag.PrintDefaults()
		return
	}

	// Generate a URL that the user must visit to authorize this command-line
	// application read-only access to the user's Github profile data
	scope := "user"       // grant access to the `users` api
	state := "FqB4EbagQ2o" // random string to protect against CSRF attacks
	url := client.AuthorizeRedirect(scope, state)

	fmt.Println("(1) Go to: " + url)
	fmt.Println("(2) Grant access, you should get back a verification code.")
	fmt.Println("(3) Enter that verification code here: ")

	// once authorized, the user is presented with a code that they must
	// enter into the command line
	var verifier string
	fmt.Scanln(&verifier)

	// create the http.Request that will access a restricted resource
	// ... notice that we include the access_token as a URL parameter
	accessToken, err := client.GrantToken(verifier)
	if err != nil {
		log.Fatal(err)
	}

	// create the http.Request that will access a restricted resource
	req, _ := http.NewRequest("GET", "https://api.github.com/user?access_token="+accessToken.AccessToken, nil)

	// make the request
	resp, err := http.DefaultClient.Do(req)
	defer resp.Body.Close()
	if err != nil {
		log.Fatal(err)
	}

	// unmarshal the body
	raw, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	user := User{}
	if err := json.Unmarshal(raw, &user); err != nil {
		log.Fatal(err)
	}

	// print the results
	fmt.Println("Hello, " + user.Login)
}

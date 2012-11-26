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
	Id         string `json:"id"`
	Name       string `json:"name"`
	Link       string `json:"link"`
	GivenName  string `json:"given_name"`
	FamilyName string `json:"family_name"`
}

var client = oauth2.Client{
	AccessTokenURL:   "https://accounts.google.com/o/oauth2/token",
	AuthorizationURL: "https://accounts.google.com/o/oauth2/auth",
	RedirectURL:      oauth2.OOB,
}

func main() {

	// You must provide the ClientId and ClientSecret as input args
	flag.StringVar(&client.ClientId, "client_id", "", "Client Id from https://code.google.com/apis/console")
	flag.StringVar(&client.ClientSecret, "client_secret", "", "Client Secret from https://code.google.com/apis/console")
	flag.Parse()

	// If ClientId or ClientSecret were not provided, exit
	if len(client.ClientId) == 0 || len(client.ClientSecret) == 0 {
		flag.PrintDefaults()
		return
	}

	// Generate a URL that the user must visit to authorize this command-line
	// application read-only access to the user's Google profile data
	url := client.AuthorizeRedirect("https://www.googleapis.com/auth/userinfo.profile", "")
	fmt.Println("(1) Go to: " + url)
	fmt.Println("(2) Grant access, you should get back a verification code.")
	fmt.Println("(3) Enter that verification code here: ")

	// once authorized, the user is presented with a code that they must
	// enter into the command line
	var verifier string
	fmt.Scanln(&verifier)

	// the code is used to request an access token
	tokens, err := client.GrantToken(verifier)
	if err != nil {
		log.Fatal(err)
	}

	// create the http.Request that will access a restricted resource
	// ... notice that we include the access_token as a URL parameter
	req, _ := http.NewRequest("GET", "https://www.googleapis.com/oauth2/v2/userinfo?access_token="+tokens.AccessToken, nil)

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
	fmt.Println("Hello, " + user.Name)
}

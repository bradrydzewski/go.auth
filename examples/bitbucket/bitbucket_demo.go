package main

import (
	"fmt"
	"flag"
    "net/http"
	"github.com/bradrydzewski/go.auth"
)

var homepage = `
<html>
	<head>
		<title>Login</title>
	</head>
	<body>
		<div>Welcome to the go.auth Bitbucket demo</div>
		<div><a href="/auth/bitbucket">Authenticate with your Bitbucket Id</a><div>
	</body>
</html>
`

var privatepage = `
<html>
	<head>
		<title>Login</title>
	</head>
	<body>
		<div>oauth url: <a href="%s" target="_blank">%s</a></div>
		<div><a href="/auth/logout">Logout</a><div>
	</body>
</html>
`

// private webpage, authentication required
func Private(w http.ResponseWriter, r *http.Request) {
	user := r.URL.User.Username()
	fmt.Fprintf(w, fmt.Sprintf(privatepage, user, user))
}

// public webpage, no authentication required
func Public(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, homepage)
}

// logout handler
func Logout(w http.ResponseWriter, r *http.Request) {
	auth.DeleteUserCookie(w, r)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func main() {

	// You should pass in your access key and secret key as args.
	// Or you can set your access key and secret key by replacing the default values below (2nd input param in flag.String)
	consumerKey := flag.String("consumer_key", "[your bitbucket consumer key]", "your oauth consumer key")
	secretKey := flag.String("secret_key", "[your bitbucket secret key]", "your oauth secret key")
	flag.Parse()

	//url that google should re-direct to
	redirect := "http://localhost:8080/auth/bitbucket"

	// set the auth parameters
	auth.Config.CookieSecret = []byte("7H9xiimk2QdTdYI7rDddfJeV")
	auth.Config.LoginSuccessRedirect = "/private"
	auth.Config.CookieSecure = false

	// login handler
	bitbucketHandler := auth.Bitbucket(*consumerKey, *secretKey, redirect)
	http.Handle("/auth/bitbucket", bitbucketHandler)

	// logout handler
    http.HandleFunc("/auth/logout", Logout)

	// public urls
	http.HandleFunc("/", Public)

	// private, secured urls
	http.HandleFunc("/private", auth.SecureFunc(Private))


	println("bitbucket demo starting on port 8080")
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		fmt.Println(err)
	}
}
















package main

import (
	"fmt"
	"flag"
    "net/http"
	"github.com/bradrydzewski/auth.go"
)

var homepage = `
<html>
	<head>
		<title>Login</title>
	</head>
	<body>
		<div>Welcome to the auth.go Github demo</div>
		<div><a href="/auth/login">Authenticate with your Github Id</a><div>
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

func main() {

	// You should pass in your access key and secret key as args.
	// Or you can set your access key and secret key by replacing the default values below (2nd input param in flag.String)
	cookieSecret := []byte("7H9xiimk2QdTdYI7rDddfJeV")
	githubAccessKey := flag.String("access_key", "[your github access key]", "your oauth access key")
	githubSecretKey := flag.String("secret_key", "[your github secret key]", "your oauth secret key")
	flag.Parse()

	// set the auth parameters
	auth.Config.CookieSecret = cookieSecret
	auth.Config.LoginSuccessRedirect = "/private"
	auth.Config.LogoutSuccessRedirect = "/"

	// get your github auth manager
	github := auth.NewGitHubAuth(*githubAccessKey, *githubSecretKey)

	// public urls
	http.HandleFunc("/", Public)

	// private, secured urls
	http.HandleFunc("/private", auth.Secure(Private))

	// logout handler
    http.HandleFunc("/auth/logout", func (w http.ResponseWriter, r *http.Request) {
		auth.LogoutRedirect(w, r)
	})
	
	// github login handler
    http.HandleFunc("/auth/login", func (w http.ResponseWriter, r *http.Request) {
		github.Authorize(w, r)
	})

	println("github demo starting on port 8080")
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		fmt.Println(err)
	}
}
















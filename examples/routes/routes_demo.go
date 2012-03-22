package main

import (
	"fmt"
	"flag"
    "net/http"
	"github.com/bradrydzewski/auth.go"
	"github.com/bradrydzewski/routes.go"
)

var homepage = `
<html>
	<head>
		<title>Login</title>
	</head>
	<body>
		<div>Welcome to the auth.go <a href='https://github.com/bradrydzewski/routes.go'>routes.go</a> demo</div>
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
	// Or you can just hardcode the values by replacing the code below (just don't checkin to a public repo!)
	cookieSecret := []byte("7H9xiimk2QdTdYI7rDddfJeV")
	githubAccessKey := flag.String("access_key", "[your github access key]", "your oauth access key")
	githubSecretKey := flag.String("secret_key", "[your github secret key]", "your oauth secret key")
	flag.Parse()

	// set the auth parameters
	auth.Config.CookieSecret = cookieSecret

	// get your github auth manager
	github := auth.NewGitHubHandler(*githubAccessKey, *githubSecretKey)

	// setup default authentication for routes
	routes.DefaultAuthHandler = auth.SecureAuthHandler

	// create the router mux
    mux := routes.New()
    mux.Get("/", Public)
    mux.Get("/private", Private).Secure()


	// logout handler
    mux.Get("/auth/logout", func (w http.ResponseWriter, r *http.Request) {
		auth.DeleteUserCookie(w, r)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})
	
	// github login handler
    mux.Get("/auth/login", func (w http.ResponseWriter, r *http.Request) {
		// attempt to get the access token
		token, err := github.GetAccessToken(r)
		if err != nil {
			//if user not authorized, redirect
			github.AuthorizeRedirect(w, r)
			return
		}

		// get the authorized user
		user, err := github.GetAuthenticatedUser(token)

		if err != nil {
			//if we can't get the user data, display an error message
			http.Error(w, "", http.StatusForbidden)
			return
		}

		// else, set the secure user cookie
		auth.SetUserCookie(w, r, user.Username())

		// redirect the user now that they are logged in
		http.Redirect(w, r, "/private", http.StatusSeeOther)
	})


	println("routes.go demo starting on port 8080")

    http.Handle("/", mux)
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		fmt.Println(err)
	}
}
















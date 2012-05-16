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
		<div>Welcome to the go.auth Google demo</div>
		<div><a href="/auth/login">Authenticate with your Google Id</a><div>
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
	googleAccessKey := flag.String("access_key", "[your google access key]", "your oauth access key")
	googleSecretKey := flag.String("secret_key", "[your google secret key]", "your oauth secret key")
	flag.Parse()

	//url that google should re-direct to
	googleRedirect := "http://localhost:8080/auth/login"

	// set the auth parameters
	auth.Config.CookieSecret = []byte("7H9xiimk2QdTdYI7rDddfJeV")
	auth.Config.LoginSuccessRedirect = "/private"

	// login handler
	googHandler := auth.Google(*googleAccessKey, *googleSecretKey, googleRedirect)
	http.Handle("/auth/login", googHandler)

	// logout handler
    http.HandleFunc("/auth/logout", Logout)

	// public urls
	http.HandleFunc("/", Public)

	// private, secured urls
	http.HandleFunc("/private", auth.SecureFunc(Private))


	println("google demo starting on port 8080")
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		fmt.Println(err)
	}
}
















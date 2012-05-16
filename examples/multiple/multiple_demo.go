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
		<div>Welcome to the go.Auth Multi-Provider demo</div>
		<div><a href="/auth/login">Login</a><div>
	</body>
</html>
`

var loginPage = `
<html>
	<head>
		<title>Login</title>
	</head>
	<body>
		<a href="/auth/login/github">Github Login</a><br/>
		<a href="/auth/login/google">Google Login</a><br/>
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

// page to choose auth provider
func MultiLogin(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, loginPage)
}

func main() {

	// You should pass in your access key and secret key as args.
	// Or you can set your access key and secret key by replacing the default values below (2nd input param in flag.String)
	googleAccessKey := flag.String("goo_access_key", "[your google access key]", "your google oauth access key")
	googleSecretKey := flag.String("goo_secret_key", "[your google secret key]", "your google oauth secret key")
	githubAccessKey := flag.String("git_access_key", "[your github access key]", "your github oauth access key")
	githubSecretKey := flag.String("git_secret_key", "[your github secret key]", "your github oauth secret key")
	flag.Parse()

	//url that google should re-direct to
	googleRedirect := "http://localhost:8080/auth/login/google"

	// set the auth parameters
	auth.Config.CookieSecret = []byte("7H9xiimk2QdTdYI7rDddfJeV")
	auth.Config.LoginSuccessRedirect = "/private"

	// create the login handlers
	google := auth.Google(*googleAccessKey, *googleSecretKey, googleRedirect)
	github := auth.Github(*githubAccessKey, *githubSecretKey)
	http.Handle("/auth/login/google", google)
	http.Handle("/auth/login/github", github)

	// login screen to choose auth provider
	http.HandleFunc("/auth/login", MultiLogin)

	// public urls
	http.HandleFunc("/", Public)

	// private, secured urls
	http.HandleFunc("/private", auth.SecureFunc(Private))

	// logout handler
    http.HandleFunc("/auth/logout", func (w http.ResponseWriter, r *http.Request) {
		auth.DeleteUserCookie(w, r)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})

	println("google demo starting on port 8080")
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		fmt.Println(err)
	}
}

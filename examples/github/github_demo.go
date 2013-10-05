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
		<div>Welcome to the go.auth Github demo</div>
		<div><a href="/auth/login">Authenticate with your Github Id</a><div>
	</body>
</html>
`

var privatepage1 = `
<html>
	<head>
		<title>Login</title>
	</head>
	<body>
		<div>oauth url: <a href="http://github.com/%s" target="_blank">%s</a></div>
		<div><a href="/auth/logout">Logout</a><div>
	</body>
</html>
`

var privatepage2 = `
<html>
	<head>
		<title>Login</title>
	</head>
	<body>
		<div><img src="%s" /></div>
		<div>oauth url: <a href="%s" target="_blank">%s</a></div>
		<div><a href="/auth/logout">Logout</a><div>
	</body>
</html>
`

// private webpage, authentication required, with User Id injected in the
// r.URL.User.Username() field
func Private1(w http.ResponseWriter, r *http.Request) {
	user := r.URL.User.Username()
	fmt.Fprintf(w, fmt.Sprintf(privatepage1, user, user))
}

// private webpage, authentication required, with User struct passed directly
// into the function
func Private2(w http.ResponseWriter, r *http.Request, user auth.User) {
	page := fmt.Sprintf(privatepage2, user.Picture(), user.Id(), user.Name())
	fmt.Fprintf(w, page)
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

	// You should pass in your client key and secret key as args.
	// Or you can set your access key and secret key by replacing the default values below (2nd input param in flag.String)
	githubClientKey := flag.String("client_key", "[your github client key]", "your oauth client key")
	githubSecretKey := flag.String("secret_key", "[your github secret key]", "your oauth secret key")
	flag.Parse()

	// set the auth parameters
	auth.Config.CookieSecret = []byte("7H9xiimk2QdTdYI7rDddfJeV")
	auth.Config.LoginSuccessRedirect = "/private2"
	auth.Config.CookieSecure = false

	// login handler
	githubHandler := auth.Github(*githubClientKey, *githubSecretKey,"")
	http.Handle("/auth/login", githubHandler)

	// logout handler
    http.HandleFunc("/auth/logout", Logout)

	// public urls
	http.HandleFunc("/", Public)

	// private, secured urls
	http.HandleFunc("/private1", auth.SecureFunc(Private1))
	http.HandleFunc("/private2", auth.SecureUser(Private2))

	println("github demo starting on port 8080")
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		fmt.Println(err)
	}
}
















# go.auth
an http authentication API for the Go programming language. Integrates with 3rd party auth providers to add security to your web application.

	go get github.com/dchest/authcookie
    go get github.com/bradrydzewski/go.auth
    
Python's Tornado framework, specifically their auth module, was the main inspiration for this library.

## Providers
The following auth providers are supported:

* Github OAuth2 [demo](https://github.com/bradrydzewski/go.auth/tree/master/examples/github)
* Google OAuth2 [demo](https://github.com/bradrydzewski/go.auth/tree/master/examples/google)
* Google OpenId [demo](https://github.com/bradrydzewski/go.auth/tree/master/examples/openid)

We plan to add support for the following providers:

* Facebook
* Twitter
* LinkedIn

# Sample Code
Example program using the Google OpenId auth provider:

```go
package main

import (
	"fmt"
	"github.com/bradrydzewski/go.auth"
	"net/http"
)

// private webpage, authentication required
func Private(w http.ResponseWriter, r *http.Request) {
	user := r.URL.User.Username()
	fmt.Fprintf(w, fmt.Sprintf(privatepage, user, user))
}

// public webpage, no authentication required
func Public(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, homepage)
}

// login success callback
func LoginSuccess(w http.ResponseWriter, r *http.Request, u auth.User) {
	auth.SetUserCookie(w, r, u.Username())
	http.Redirect(w, r, "/private", http.StatusSeeOther)
}

// login failure callback
func LoginFailure(w http.ResponseWriter, r *http.Request, err error) {
	http.Error(w, err.Error(), http.StatusForbidden)
}

func main() {

	// set the auth parameters
	auth.Config.CookieSecret = []byte("7H9xiimk2QdTdYI7rDddfJeV")

	// create the auth multiplexer
	googleHandler := auth.NewGoogleOpenIdHandler()
	authMux := auth.NewAuthMux(LoginSuccess, LoginFailure)
	authMux.Handle("/auth/login", googleHandler)

	// public urls
	http.HandleFunc("/", Public)

	// private, secured urls
	http.HandleFunc("/private", auth.Secure(Private))

	// login handler
	http.Handle("/auth/login", authMux)

	println("openid demo starting on port 8080")
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		fmt.Println(err)
	}
}
```

## User data
The user data is passed to your Handler via the URL's `User` field:

```go
func Foo(w http.ResponseWriter, r *http.Request) {
	user := r.URL.User.Username()
}
```

# Configuration
`auth.go` uses the following default parameters which can be configured:

<table>
<tr>
 <th>Variable</th>
 <th>Description</th>
 <th>Default Value</th>
</tr>
<tr>
 <td>auth.Config.CookieName</td>
 <td>name of the secure cookie</td>
 <td>"UID"</td>
</tr>
<tr>
 <td>auth.Config.CookieSecret</td>
 <td>key used to encrypt the cookie value</td>
 <td>nil</td>
</tr>
<tr>
 <td>auth.Config.CookieExp</td>
 <td>amount of time before cookie expires</td>
 <td>time.Hour * 24 * 14</td>
</tr>
<tr>
 <td>auth.Config.LoginRedirect</td>
 <td>where to re-direct a user that is not authenticated</td>
 <td>"/auth/login"</td>
</tr>
</table>

Example:

```go
auth.Config.LoginRedirect = "/auth/login"
```


# go.auth
an http authentication API for the Go programming language. Integrates with 3rd party auth providers to add security to your web application.

	go get github.com/dchest/authcookie
    go get github.com/bradrydzewski/go.auth
    
Python's Tornado framework, specifically their auth module, was the main inspiration for this library.

## Providers
The following auth providers are supported:

* Github OAuth 2.0 [demo](https://github.com/bradrydzewski/go.auth/tree/master/examples/github)
* Google OAuth 2.0 [demo](https://github.com/bradrydzewski/go.auth/tree/master/examples/google)
* Google OpenId 2.0 [demo](https://github.com/bradrydzewski/go.auth/tree/master/examples/openid)
* Twitter OAuth 1.0a [demo](https://github.com/bradrydzewski/go.auth/tree/master/examples/twitter)

See the [multi-provider](https://github.com/bradrydzewski/go.auth/tree/master/examples/multiple) demo application to provide your users multiple login options.

We plan to add support for the following providers:

* Facebook
* LinkedIn

# Sample Code
Example program using the Github OAuth auth provider:

```go
// Set the default authentication configuration parameters
auth.Config.CookieSecret         = []byte("asdfasdfasfasdfasdfafsd")
auth.Config.LoginRedirect        = "/auth/login" // send user here to login
auth.Config.LoginSuccessRedirect = "/private"    // send user here post-login

// Create your login handler
githubHandler := auth.Github(githubAccessKey, githubSecretKey)
http.Handle("/auth/login", githubHandler)

// Example of a public http handler
http.HandleFunc("/public", Public)

// Example of a secured http handler
http.HandleFunc("/private", auth.SecureFunc(Private))
```

## User data
The `auth.SecureFunc` wraps a standard `http.HandlerFunc` and injects the username
into the http request's `r.URL.User.Username()` field:

```go
func Private(w http.ResponseWriter, r *http.Request) {
	user := r.URL.User.Username()
}
```

If you want additional user data you must implement our custom handler, and wrap
it with the `auth.SecureUserFunc`. This adds an additional `User` parameter to
your method signature that provides the full set of available user data:

```go
func Private(w http.ResponseWriter, r *http.Request, u auth.User) {
	username := u.Id()
	fullname := u.Name()
	avatar := u.Picture()
	email := u.Email()
	...
}

http.HandleFunc("/foo", auth.SecureUserFunc(Private))
```

# Configuration
`go.auth` uses the following default parameters which can be configured:

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
<tr>
 <td>auth.Config.LoginSuccessRedirect</td>
 <td>where to re-direct a user once authenticated</td>
 <td>"/"</td>
</tr>
</table>

Example:

```go
auth.Config.LoginRedirect = "/auth/login/google"
```

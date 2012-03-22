# auth.go
an http authentication API for the Go programming language. Integrates with 3rd party auth providers to add security to your web application. Current Github and Google Oauth2 are supported.

	go get github.com/dchest/authcookie
    go get github.com/bradrydzewski/auth.go
    
Python's Tornado framework, specifically their auth module, was the main inspiration for this library.

## Getting Started

    package main

    import (
        "fmt"
        "github.com/bradrydzewski/auth.go"
        "net/http"
    )

    func AccountInfo(w http.ResponseWriter, r *http.Request) {
        user := r.URL.User.Username()
        fmt.Fprintf(w, "account info for %s", user)
    }
    
    func BillingInfo(w http.ResponseWriter, r *http.Request) {
        user := r.URL.User.Username()
        fmt.Fprintf(w, "billing info for %s", user)
    }

    func main() {

        // Configure the secure cookie secret
        auth.Config.CookieSecret = []byte("7H9xiimk2QdTdYI7rDddfJeV")
        
        // Setup Github oauth
        githubAccessKey := "wasdfoijlkwejiojdsklfjls"
        githubSecretKey := "sdlfkjsdfkljwelkjsdklfjsdfslkdfjwlk"
        github := auth.NewGitHubAuth(githubAccessKey, githubSecretKey)
        
        // Restricted URLs
        http.HandleFunc("/", auth.Secure(WelcomeScreen))
        http.HandleFunc("/account", auth.Secure(AccountInfo))
        http.HandleFunc("/billing", auth.Secure(BillingInfo))
        
        // Login / Logout Pages
        http.HandleFunc("/auth/logout", func (w http.ResponseWriter, r *http.Request) {
			auth.DeleteUserCookie(w, r)
			http.Redirect(w, r, "/", http.StatusSeeOther)
        })
		http.HandleFunc("/auth/login",  func (w http.ResponseWriter, r *http.Request) {
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

        http.ListenAndServe(":8080", nil)
    }

### Breakdown
Let's breakdown each block of code in the above example.

First we set the Cookie secret. User session are stored in secure cookies, using the authcookie library:

    auth.Config.CookieSecret = []byte("7H9xiimk2QdTdYI7rDddfJeV")

Note: you can (and should) generate a unique key using the following unix command:

    $> openssl rand -hex 32
    $> eae007a2b632ececad1a42ce074e3f84015d6dcb624a3d0a86b9612e196464aa

Then we create an instance of a Github Oauth provider. We pass in our Github client id and secret key:

    github := auth.NewGitHubAuth(githubAccessKey, githubSecretKey)

Then we add our handlers using the standard `net/http` library:

    http.HandleFunc("/auth", AccountInfo)
    
We can easily secure this URL by wrapping it in the `Secure` function:

    http.HandleFunc("/auth", auth.Secure(AccountInfo))
    
By default, `auth.go` will route any unauthenticated users to `/auth/login`. Therefore we need to create a route for `/auth/login` that initiates the Github Oauth login flow:

    http.HandleFunc("/auth/login",  func (w http.ResponseWriter, r *http.Request) {
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


### User data
The user data is passed to your Handler via the URL's `User` field:

    func MyHandler(w http.ResponseWriter, r *http.Request) {
        user := r.URL.User.Username()
    }
    
## Configuration
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
<tr>
 <td>auth.Config.LoginSuccessRedirect</td>
 <td>where to re-direct a user after successful auth</td>
 <td>"/"</td>
</tr>
<tr>
 <td>auth.Config.LogoutSuccessRedirect</td>
 <td>where to re-direct a user after logout</td>
 <td>"/auth/login"</td>
</tr>
</table>

Example:

    auth.Config.LoginRedirect = "/login"
    
## routes.go
To integrate with the [routes.go](https://github.com/bradrydzewski/routes.go) library check out the `/examples/routes` demo application.

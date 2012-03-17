# auth.go
an http authentication API for the Go programming language. Integrates with 3rd party auth providers to add security to your web application. Current Github and Google Oauth2 are supported.

    go get github.com/bradrydzewski/auth.go
    
you will first need to install the following dependencies:

    go get github.com/dchest/authcookie

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
        http.HandleFunc("/auth/login",  func (w http.ResponseWriter, r *http.Request) { github.Authorize(w, r) })
        http.HandleFunc("/auth/logout", func (w http.ResponseWriter, r *http.Request) { auth.LogoutRedirect(w, r) })

        http.ListenAndServe(":8080", nil)
    }

## Breakdown
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
        github.Authorize(w, r)
    })
    
## User data
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
 <td>CookieName</td>
 <td>name of the secure cookie</td>
 <td>"UID"</td>
</tr>
<tr>
 <td>CookieSecret</td>
 <td>key used to encrypt the cookie value</td>
 <td>none, must be set by user</td>
</tr>
<tr>
 <td>CookieExp</td>
 <td>amount of time before cookie expires</td>
 <td>time.Hour * 24 * 14</td>
</tr>
<tr>
 <td>LoginRedirect</td>
 <td>where to re-direct a user that is not authenticated</td>
 <td>"/auth/login"</td>
</tr>
<tr>
 <td>LoginSuccessRedirect</td>
 <td>where to re-direct a user after successful auth</td>
 <td>"/"</td>
</tr>
<tr>
 <td>LogoutSuccessRedirect</td>
 <td>where to re-direct a user after logout</td>
 <td>"/auth/login"</td>
</tr>
</table>

Example:

    auth.Config.LoginSuccessRedirect = "/account"
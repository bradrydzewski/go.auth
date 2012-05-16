Demo for authenticating a user with <b>multiple Oauth2 providers</b>. In this example you can authenticate with either Google <b>OR</b> Github Oauth2.

Running the demo requires some basic setup and configuration, detailed below. It is assumed you have successfully ran the individual Google and Github demos prior to this one.

###Configuration
For this demo we have changed the redirect URLs to:

* Google: http://localhost:8080/auth/login/google
* Github: http://localhost:8080/auth/login/github

You should login to the Google API console and register the second URL. You will also need to login to Github and register a new application for this URL (because Github can only have 1 redirect URL per application)

###Required Flags
In order to start the application you will need to pass in the Client Id and Secret Key as args for both Google and Github:

```sh
./multiple -goo_access_token 121a40934a69c7cca3b3 -goo_secret_key asdfasdf234wfsf387s8f79asdfc41f49814k9asdasd \
           -git_access_token a69c7cca3b3121a40934 -git_secret_key 9fd798we87s8f79904abaa91ac1ac41f49814k9asdfs
```

You can then visit your application at `http://localhost:8080/`

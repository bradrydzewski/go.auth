Demo for authenticating a user with the <b>Google OAuth2</b> API.

Running the demo requires some basic setup and configuration, detailed below.

###Register Application
You will need to login to your Google API Console and [register an application](https://code.google.com/apis/console) to get a Access Key and Secret Key.

* Go to [https://code.google.com/apis/console](https://code.google.com/apis/console)
* Create a new project, and then click the "API Access" link from the nav menu
* Click the "Create OAuth2 Client Id" button, and fill out the required info
* When prompted, specify the following Redirect URL: `http://localhost:8080/auth/login`

When you click the Register Application button you will be given the Client Id and Secret Key, which will look something like this:

    ClientId:      a69c7cca3b3121a40934
    ClientSecret:  1ac41f49814k9asdfs9fd798we87s8f79904abaa91ac.apps.googleusercontent.com

###Required Flags
In order to start the application you will need to pass in the Client Id and Secret Key as args:

    ./google -access_key a69c7cca3b3121a40934 -secret_key 1ac41f49814k9asdfs9fd798we87s8f79904abaa91ac

You can then visit your application at `http://localhost:8080/`

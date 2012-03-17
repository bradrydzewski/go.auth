#Github Demo
Demo for authenticating a user with the Github OAuth2 API.

##Required Configuration
Running the demo requires some basic setup and configuration, detailed below.

###Register Application
You will need to login to your Github account and [register an application](https://github.com/settings/applications) to get a Client Id and Secret Key.

* Go to [https://github.com/settings/applications](https://github.com/settings/applications)
* Click the "Register New Application" button
* Give your application an awesome name
* Set the Main URL to `http://localhost:8080/`
* Set the Callback URL to `http://localhost:8080/auth/login/github`
* Click the "Register Application" button

When you click the Register Application button you will be given the Client Id and Secret Key, which will look something like this:

    ClientId: a69c7cca3b3121a40934
    Secret:   1ac41f49814k9asdfs9fd798we87s8f79904abaa91ac

###Required Flags
In order to start the application you will need to pass in the Client Id and Secret Key as args:

   ./6.out -access_token a69c7cca3b3121a40934 -secret_key 1ac41f49814k9asdfs9fd798we87s8f79904abaa91ac



# angular-oauth1-client
An OAuth1.0a client for AngularJS and Cordova/Ionic

## Getting Started

### Install this plugin with the dependencies

    $ bower install angular-oauth1-client

Make sure to include these in your `index.html`:

* [Underscore](http://underscorejs.org)
* [CryptoJS/Hmac-Sha1 and Base64 libraries](https://github.com/sytelus/CryptoJS)
* [Angular Local Storage](https://github.com/grevory/angular-local-storage)
* angular-oauth1-client (this repository)

For example, `index.html`:

    <script src="lib/underscore/underscore-min.js"></script>
    <script src="lib/cryptojslib/rollups/hmac-sha1.js"></script>
    <script src="lib/cryptojslib/components/enc-base64-min.js"></script>
    <script src="lib/angular-local-storage/dist/angular-local-storage.min.js"></script>
    <script src="lib/angular-oauth1-client/dist/angular-oauth1-client.min.js"></script>

Make sure to install the [`cordova-plugin-inappbrowser` plugin](https://github.com/apache/cordova-plugin-inappbrowser):

    $ ionic plugin add cordova-plugin-inappbrowser

    or

    $ cordova plugin add cordova-plugin-inappbrowser


## Usage

First you need to configure oauth1Client with your API data. Include oauth1Client as a dependency in your app definition:

    angular.module('myModule', [
        'oauth1Client'
    ])

    .config(function(oauth1ClientProvider) {
        oauth1ClientProvider.config({
            consumerKey: '~~YOUR~CONSUMER~KEY~~',
            consumerSecret: '~~YOUR~CONSUMER~SECRET~~',
            requestEndpoint: 'http://localhost/wordpress/oauth1/request',
            authorizeEndpoint: 'http://localhostwordpress/oauth1/authorize',
            accessEndpoint: 'http://localhost/wordpress/oauth1/access',
            oauthCallback: 'http://www.google.com'
        });
    })

Then start the authorization flow in your controller. This will open up the InAppBrowser and ask the user to approve your app's access:

    var authorizationProcess = oauth1Client.authorize();

After authorization, you are returned a wrapper around angular's $http that takes the same parameters and configs, but adds the OAuth authorization information to it:

    authorizationProcess.then(function(authorizedHttp) {
        authorizedHttp({
            method: "POST",
            url: "http://localhost/wordpress/wp-json/users",
            data: {
                username: "User 2",
                name: "User 2",
                password: "User 2's Password",
                email: "email2@email.com"
            }
        })
        .then(function(response) {
            alert("New user created!");
        }, function(response) {
            alert("Error! " + response.data);
        });
        authorizedHttp({
            method: "GET",
            url: "http://localhost/wordpress/wp-json/users/me"
        })
        .then(function(response) {
            alert("Success! " + JSON.stringify(response));
        },
        function(response) {
            alert("Error! " + JSON.stringify(response));
        });
    });

### Wordpress API Setup
If you are using the [Wordpress WP-API](https://wordpress.org/plugins/json-rest-api/) you will need to set up the OAuth 1.0a server on your instance. See setup instructions at the [WP REST API - OAuth 1.0a Server page](http://oauth1.wp-api.org/index.html).

## Additional Information

Some things to note:

1. WP-API Version - This plugin was originally built to use the Wordpress JSON API (WP-API) version 1. It has not been tested with [version 2](https://wordpress.org/plugins/rest-api/).
2. `CORS` support - You will most likely need to enable CORS support on your Wordpress API. For development, a [library by `thenbrent`](https://github.com/thenbrent/WP-API-CORS) will provide CORS support. As mentioned there, you will probably want to harden your server more in production.
3. `deviceready` event - This plugin makes use of the [Cordova InAppBrowser plugin](https://github.com/apache/cordova-plugin-inappbrowser). Cordova plugins only work when the `deviceready` event fires. See the plugin README for more details.
4. Callback url - You may specify any callback url you like, *as long as* it actually resolves to a real website. There have been some issues with, for example, putting `http://localhost` when you aren't running anything on `localhost` or it isn't accessible from the iOS simulator.

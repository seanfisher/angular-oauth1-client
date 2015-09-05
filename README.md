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

Example usage would be to put this in your controller:

    var authorizationProcess = oauth1Client.authorize();

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
            .success(function(data, status, headers, config) {
                alert("New user created!");
            })
            .error(function(data, status, headers, config) {
                alert("Error! " + data);
            });
        authorizedHttp({
            method: "GET",
            url: "http://localhost/wordpress/wp-json/users/me"
        })
            .success(function(data, status, headers, config) {
                alert(data);
            })
            .error(function(data, status, headers, config) {
                alert("Error! " + data);
            });
    }

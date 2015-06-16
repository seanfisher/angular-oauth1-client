# angular-oauth1-client
An OAuth1.0a client for AngularJS

## Getting Started
Make sure to include these in your `index.html`:

    Underscore
    CryptoJS/Hmac-Sha1 and Base64 libraries
    Angular Local Storage
    angular-oauth1-client

Make sure to install the `cordova-plugin-inappbrowser` plugin.

For example, `index.html`:

    <script src="lib/underscore/underscore-min.js"></script>
    <script src="lib/cryptojslib/rollups/hmac-sha1.js"></script>
    <script src="lib/cryptojslib/components/enc-base64-min.js"></script>
    <script src="lib/angular-local-storage/dist/angular-local-storage.min.js"></script>
    <script src="lib/angular-oauth1-client/src/angular-oauth1-client.js"></script>
## Usage

Example usage would be to put this in your `controller`:

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

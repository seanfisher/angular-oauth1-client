module.exports = function(config) {
    config.set({
        files: [
            'bower_components/angular/angular.js',
            'bower_components/angular-mocks/angular-mocks.js',
            'bower_components/angular-local-storage/dist/angular-local-storage.js',
            'bower_components/cryptojslib/rollups/hmac-sha1.js',
            'bower_components/cryptojslib/components/enc-base64.js',
            'src/*.js',
            'test/*.js'
        ],

        autoWatch: true,

        frameworks: ['jasmine'],

        browsers: [
            'PhantomJS'
        ],

        plugins: [
            'karma-phantomjs-launcher',
            'karma-jasmine'
        ],

        reporters: ['progress']

    });
};

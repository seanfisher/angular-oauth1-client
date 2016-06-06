describe('oauth1AuthorizedHttp', function() {

    var $httpBackend, oauth1Signer, oauth1AuthorizedHttp;

    beforeEach(module('oauth1Client'));

    beforeEach(inject(function(_$httpBackend_, _oauth1Signer_, _oauth1AuthorizedHttp_) {
        $httpBackend = _$httpBackend_;
        oauth1Signer = _oauth1Signer_;
        oauth1AuthorizedHttp = _oauth1AuthorizedHttp_;
    }));

    afterEach(function() {
        $httpBackend.verifyNoOutstandingExpectation();
        $httpBackend.verifyNoOutstandingRequest();
    });

    var config = {
        consumerKey: 'boshGesvuWojyemWicsoshEctUsicEpt',
        consumerSecret: 'foovmunsEdOvsocmouthdikAkCidErUj',
        timestamp: 314159,
        nonce: 'corWyctucdeWeizufCerkyodPhivcuIt',
        token: 'OtDohepDyikAjMatbealCecdixJucgee',
        tokenSecret: 'ciphelonnishCewaipEdIatfodEshJia'
    };

    it('signs a $http request', function() {
        $httpBackend.when('GET', '/foo/bar').respond(function(method, url, data, headers) {
            expect(headers['Authorization']).toBe('OAuth oauth_consumer_key="boshGesvuWojyemWicsoshEctUsicEpt", oauth_nonce="corWyctucdeWeizufCerkyodPhivcuIt", oauth_timestamp="314159", oauth_signature_method="HMAC-SHA1", oauth_token="OtDohepDyikAjMatbealCecdixJucgee", oauth_version="1.0", oauth_signature="Qmhw%2Bz1oQ5bQhPt82ZONhHhV%2FKI%3D"');
            expect(headers['Content-Type']).toBe('application/x-www-form-urlencoded; charset=UTF-8');
            expect(data).toBe('{"foo":"bar"}');
            return headers;
        });
        $httpBackend.expectGET('/foo/bar');
        var signer = oauth1Signer.create(config);
        var http = oauth1AuthorizedHttp.create(signer);
        http({
            method: 'GET',
            url: '/foo/bar',
            data: {foo: 'bar'}
        });
        $httpBackend.flush();

    });

});

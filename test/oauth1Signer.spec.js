describe('oauth1Signer', function() {

    beforeEach(module('oauth1Client'));

    beforeEach(inject(function($httpBackend, oauth1Signer) {
        this.$httpBackend = $httpBackend;
        this.oauth1Signer = oauth1Signer;
    }));

    var config = {
        url: 'foobar',
        consumerKey: 'boshGesvuWojyemWicsoshEctUsicEpt',
        consumerSecret: 'foovmunsEdOvsocmouthdikAkCidErUj',
        timestamp: 314159,
        nonce: 'corWyctucdeWeizufCerkyodPhivcuIt'
    };
    var configWithToken = angular.extend({
        token: 'OtDohepDyikAjMatbealCecdixJucgee',
        tokenSecret: 'ciphelonnishCewaipEdIatfodEshJia'
    }, config);

    it('builds a correct signed URL', function() {
        var signer = this.oauth1Signer.create(config);
        expect(signer.signedUrl()).toBe('foobar?oauth_consumer_key=boshGesvuWojyemWicsoshEctUsicEpt&oauth_nonce=corWyctucdeWeizufCerkyodPhivcuIt&oauth_signature_method=HMAC-SHA1&oauth_timestamp=314159&oauth_version=1.0&oauth_signature=udcmNhjNHoUlblxuYCB7LIvSR0o%3D');
    });

    it('builds a correct signed URL', function() {
        var signer = this.oauth1Signer.create(configWithToken);
        expect(signer.signedUrl()).toBe('foobar?oauth_consumer_key=boshGesvuWojyemWicsoshEctUsicEpt&oauth_nonce=corWyctucdeWeizufCerkyodPhivcuIt&oauth_signature_method=HMAC-SHA1&oauth_timestamp=314159&oauth_token=OtDohepDyikAjMatbealCecdixJucgee&oauth_version=1.0&oauth_signature=FxfYmMVfatIxUcNMgloC9aViCcU%3D');
    });

    it('builds a correct authorization header', function() {
        var signer = this.oauth1Signer.create(configWithToken);
        expect(signer.authorizationHeader()).toBe('oauth_consumer_key="boshGesvuWojyemWicsoshEctUsicEpt", oauth_nonce="corWyctucdeWeizufCerkyodPhivcuIt", oauth_timestamp="314159", oauth_signature_method="HMAC-SHA1", oauth_token="OtDohepDyikAjMatbealCecdixJucgee", oauth_version="1.0", oauth_signature="FxfYmMVfatIxUcNMgloC9aViCcU%3D"');
    });

});

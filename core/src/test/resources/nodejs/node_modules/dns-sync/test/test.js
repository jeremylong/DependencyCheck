'use strict';

var assert = require('assert'),
    dnsSync = require('../index');

describe('dns sync', function () {

    it('should resolve dns', function () {
        assert.ok(dnsSync.resolve('www.example.com'));
        assert.ok(dnsSync.resolve('www.paypal.com'));
        assert.ok(dnsSync.resolve('www.google.com'));
        assert.ok(dnsSync.resolve('www.yahoo.com'));
    });

    it('should fail to resolve dns', function () {
        assert.ok(!dnsSync.resolve('www.example.con'));
        assert.ok(!dnsSync.resolve('www.paypal.con'));
        assert.ok(!dnsSync.resolve('www.not-google.first'));
        assert.ok(!dnsSync.resolve('www.hello-yahoo.next'));
    });

    it('should fail to resolve valid dns', function () {
        assert.ok(!dnsSync.resolve("$(id > /tmp/foo)'"));
        assert.ok(!dnsSync.resolve("cd /tmp; rm -f /tmp/echo; env 'x=() { (a)=>\' bash -c \"echo date\"; cat /tmp/echo"));
        assert.ok(!dnsSync.resolve("$(grep -l -z '[^)]=() {' /proc/[1-9]*/environ | cut -d/ -f3)'"));
    });

    it('should resolve AAAA records if asked', function () {
        var aaaa = dnsSync.resolve('www.google.com', 'AAAA');
        assert.ok(aaaa);
        assert.ok(aaaa[0].match(/^([0-9a-f]{2,4}(:|$))+/));
        assert.ok(dnsSync.resolve('www.google.com') !== aaaa);
    });

    it('should resolve NS records if asked', function () {
        var ns = dnsSync.resolve('google.com', 'NS');
        assert.ok(ns);
        assert.ok(ns.length >= 1);
        assert.ok(ns[0].match(/^ns[0-9]+\.google\.com$/));
    });
});

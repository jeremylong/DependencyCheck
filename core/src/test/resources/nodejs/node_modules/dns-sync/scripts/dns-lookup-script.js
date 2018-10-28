'use strict';

var dns = require('dns'),
    debug = require('debug')('dns-sync'),
    name, type, fn;

for (var i = 0; i < process.argv.length; i++) {
	if (process.argv[i].indexOf('dns-lookup-script') >= 0) {
		name = process.argv[i + 1];
		type = process.argv[i + 2];
		fn = type ? dns.resolve.bind(dns, name, type) : dns.lookup.bind(dns, name);
		break;
	}
}

fn(function (err, ip) {
    if (err) {
        debug(err);
        process.exit(1);
    } else {
        debug(name, 'resolved to', ip);
        process.stdout.write(JSON.stringify(ip));
    }
});

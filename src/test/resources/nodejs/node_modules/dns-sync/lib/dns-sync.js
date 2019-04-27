'use strict';

var net = require('net'),
    util = require('util'),
    path = require('path'),
    shell = require('shelljs'),
    debug = require('debug')('dns-sync');

//source - http://stackoverflow.com/questions/106179/regular-expression-to-match-dns-hostname-or-ip-address
var ValidHostnameRegex = new RegExp("^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$");

function isValidHostName(hostname) {
    return ValidHostnameRegex.test(hostname);
}
/**
 * Resolve hostname to IP address,
 * returns null in case of error
 */
module.exports = {
    lookup: function lookup(hostname) {
        return module.exports.resolve(hostname);
    },
    resolve: function resolve(hostname, type) {
        var output,
            nodeBinary = process.execPath;

        if (!isValidHostName(hostname)) {
            console.error('Invalid hostname:', hostname);
            return null;
        }

        var scriptPath = path.join(__dirname, "../scripts/dns-lookup-script"),
            response,
            cmd = util.format('"%s" "%s" %s %s', nodeBinary, scriptPath, hostname, type || '');

        response = shell.exec(cmd, {silent: true});
        if (response && response.code === 0) {
            return JSON.parse(response.output);
        }
        debug('hostname', "fail to resolve hostname " + hostname);
        return null;
    }
};
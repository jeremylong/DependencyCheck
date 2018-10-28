'use strict';

var Benchmark = require('benchmark');

var dnsSync = require('../index');


var suite = new Benchmark.Suite();

suite.add('success case', function() {
    return dnsSync.resolve('www.example.com');
})
.add('failure case', function() {
  return dnsSync.resolve('www.example.con');
})
.on('cycle', function(event) {
  console.log(String(event.target));
})
.run({ 'async': true });
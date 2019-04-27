'use strict'
/* global describe it is mock unmock */

var cwd = process.cwd()
var cache = require.cache
var runJs = cwd + '/run.js'

describe('resolve', function () {
  it('logs an error if there is no package.json', function (done) {
    mock(console, {
      error: mock.count()
    })
    mock(process, {
      exit: function () {
        is(console.error.value, 1)
        unmock(console)
        unmock(process)
        process.chdir(cwd)
        done()
      }
    })
    process.chdir(__dirname)
    delete cache[runJs]
    require('../run')
  })
})

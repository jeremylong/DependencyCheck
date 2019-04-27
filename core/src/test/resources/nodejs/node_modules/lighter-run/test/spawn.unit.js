'use strict'
/* global describe it is mock unmock beforeEach afterEach */

var config = require('lighter-config')
var cp = require('child_process')
var Child = require('./helpers/child.helper.js')
var cwd = process.cwd()
var stdout = process.stdout
var write = stdout.write
var cache = require.cache
var runJs = cwd + '/run.js'

describe('spawn', function () {
  beforeEach(function () {
    mock(config, {
      lighterRun: {
        minRestartDelay: 1,
        maxRestartDelay: 4,
        restartDelayBackoff: 2,
        cleanTime: 20
      }
    })
    mock(stdout, {
      write: function () {}
    })
  })

  afterEach(function () {
    unmock(config)
    unmock(cp)
    unmock(process)
    stdout.write = write
  })

  it('spawns a child process', function (done) {
    mock(cp, {
      spawn: function (node, args) {
        is.string(node)
        is.array(args)
        setTimeout(done, 1)
        return new Child()
      }
    })
    delete cache[runJs]
    require('../run')
  })

  it('restarts the child process when it dies', function (done) {
    var spawnCount = 0
    mock(cp, {
      spawn: function (node, args) {
        var child = new Child()
        if (spawnCount++) {
          done()
        } else {
          setTimeout(function () {
            child.close()
          }, 1)
        }
        return child
      }
    })
    delete cache[runJs]
    require('../run')
  })

  it('passes child arguments found after a double-dash', function (done) {
    var spawnCount = 0
    mock(process, {
      argv: ['/usr/local/bin/node', '/usr/local/bin/lr', '--', '--port', '8080']
    })
    mock(cp, {
      spawn: function (node, args) {
        is(args[1], '--port')
        is(args[2], '8080')
        setTimeout(done, 1)
        return new Child()
      }
    })
    delete cache[runJs]
    require('../run')
  })

  it('uses an optional file argument', function (done) {
    var spawnCount = 0
    mock(process, {
      argv: ['/usr/local/bin/node', '/usr/local/bin/lr', 'this.js']
    })
    mock(cp, {
      spawn: function (node, args) {
        is(args[0], 'this.js')
        setTimeout(done, 1)
        return new Child()
      }
    })
    delete cache[runJs]
    require('../run')
  })

  it('uses an optional file argument found before double dashes', function (done) {
    var spawnCount = 0
    mock(process, {
      argv: ['/usr/local/bin/node', '/usr/local/bin/lr', 'this.js', '--', '--that', 'THE_OTHER']
    })
    mock(cp, {
      spawn: function (node, args) {
        is(args[0], 'this.js')
        is(args[1], '--that')
        is(args[2], 'THE_OTHER')
        setTimeout(done, 1)
        return new Child()
      }
    })
    delete cache[runJs]
    require('../run')
  })

  it('writes output once the new child process runs cleanly', function (done) {
    var spawnCount = 0
    var child = new Child()
    mock(stdout, {
      write: mock.args()
    })
    mock(cp, {
      spawn: function (node, args) {
        ++spawnCount
        if (spawnCount < 4) {
          setTimeout(function () {
            stdout.write('Spawn ' + spawnCount + '.')
            child.close()
          }, spawnCount * 10)
        } else {
          setTimeout(done, 1)
        }
        child = new Child()
        return child
      }
    })
    delete cache[runJs]
    require('../run')
  })

  it('skips the dot if the child was killed manually', function (done) {
    var spawnCount = 0
    var child = new Child()
    mock(stdout, {
      write: mock.args()
    })
    mock(cp, {
      spawn: function (node, args) {
        ++spawnCount
        if (spawnCount < 4) {
          setTimeout(function () {
            stdout.write('Spawn ' + spawnCount + '.')
            child.killed = true
            child.close()
          }, spawnCount * 10)
        } else {
          is.same(stdout.write.value, [
            {'0': 'Spawn 1.'},
            {'0': ''},
            {'0': 'Spawn 3.'},
            {'0': '\n'}
          ])
          setTimeout(done, 1)
        }
        child = new Child()
        return child
      }
    })
    delete cache[runJs]
    require('../run')
  })
})

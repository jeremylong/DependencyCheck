'use strict'
/* global describe it is mock unmock */

if (process.platform === 'darwin') {
  require('fsevents')
  var cp = require('child_process')
  var cwd = process.cwd()
  var cache = require.cache
  var runJs = cwd + '/run.js'
  var fseventsJs = cwd + '/node_modules/fsevents/fsevents.js'
  var noop = function () {}
  var fakeStream = {
    pipe: noop,
    on: noop,
    emit: noop
  }

  describe('watcher', function () {
    it('listens for changes and kills the child process', function (done) {
      var fsevents = cache[fseventsJs]
      var changed
      mock(console, {
        log: mock.args()
      })
      mock(cp, {
        spawn: function (node, args) {
          return {
            on: noop,
            stdout: fakeStream,
            stderr: fakeStream,
            kill: function () {
              is.in(console.log.value[0][0], 'Deleted "/tmp/test.txt"')
              unmock(console)
              unmock(cp)
              unmock(fsevents)
              done()
            }
          }
        }
      })
      mock(fsevents, {
        exports: function () {
          return {
            on: function (type, fn) {
              changed = fn
            },
            start: noop
          }
        }
      })
      delete cache[runJs]
      require('../run')
      changed('/tmp/test.txt', {
        path: '/tmp/test.txt',
        event: 'deleted'
      })
    })

    it('removes the current directory from the file path', function (done) {
      var fsevents = cache[fseventsJs]
      var changed
      mock(console, {
        log: mock.args()
      })
      mock(cp, {
        spawn: function (node, args) {
          return {
            on: noop,
            stdout: fakeStream,
            stderr: fakeStream,
            kill: function () {
              is.in(console.log.value[0][0], 'Modified "test/watcher.unit.js"')
              unmock(console)
              unmock(cp)
              unmock(fsevents)
              done()
            }
          }
        }
      })
      mock(fsevents, {
        exports: function () {
          return {
            on: function (type, fn) {
              changed = fn
            },
            start: mock.count()
          }
        }
      })
      delete cache[runJs]
      require('../run')
      changed(__filename, {
        path: __filename,
        event: 'modified'
      })
    })

    it('only kills the child process once', function (done) {
      var fsevents = cache[fseventsJs]
      var killCount = 0
      var child = {
        on: noop,
        stdout: fakeStream,
        stderr: fakeStream,
        kill: function () {
          killCount++
          this.killed = true
        }
      }
      var changed
      mock(console, {
        log: mock.count()
      })
      mock(cp, {
        spawn: function (node, args) {
          return child
        }
      })
      mock(fsevents, {
        exports: function () {
          return {
            on: function (type, fn) {
              changed = fn
            },
            start: mock.count()
          }
        }
      })
      delete cache[runJs]
      require('../run')
      changed(__filename, {
        path: __filename,
        event: 'modified'
      })
      changed(__filename, {
        path: __filename,
        event: 'deleted'
      })
      setTimeout(function () {
        is(console.log.value, 1)
        is(killCount, 1)
        unmock(console)
        unmock(cp)
        unmock(fsevents)
        done()
      }, 1)
    })

    it('writes live-reloadable paths to child.stdin instead of killing the child process', function (done) {
      var fsevents = cache[fseventsJs]
      var changed
      mock(console, {
        log: noop
      })
      mock(cp, {
        spawn: function (node, args) {
          return {
            on: noop,
            stdout: fakeStream,
            stderr: fakeStream,
            stdin: {
              write: function (output) {
                is.string(output)
                unmock(console)
                unmock(cp)
                unmock(fsevents)
                done()
              }
            }
          }
        }
      })
      mock(fsevents, {
        exports: function () {
          return {
            on: function (type, fn) {
              changed = fn
            },
            start: noop
          }
        }
      })
      delete cache[runJs]
      require('../run')
      changed(cwd + '/public/favicon.ico', {
        path: cwd + '/public/favicon.ico',
        event: 'created'
      })
    })

    it('allows live-reload configuration via config.lighterRun.live', function (done) {
      var fsevents = cache[fseventsJs]
      var config = require('lighter-config')
      var changed
      mock(config, {
        lighterRun: {
          live: '/*.log'
        }
      })
      mock(console, {
        log: noop
      })
      mock(cp, {
        spawn: function (node, args) {
          return {
            on: noop,
            stdout: fakeStream,
            stderr: fakeStream,
            stdin: {
              write: function (output) {
                is.string(output)
                unmock(config)
                unmock(console)
                unmock(cp)
                unmock(fsevents)
                done()
              }
            }
          }
        }
      })
      mock(fsevents, {
        exports: function () {
          return {
            on: function (type, fn) {
              changed = fn
            },
            start: noop
          }
        }
      })
      delete cache[runJs]
      require('../run')
      changed(cwd + '/run.log', {
        path: cwd + '/run.log',
        event: 'modified'
      })
    })

    it('allows ignore configuration via config.lighterRun.ignore', function (done) {
      var fsevents = cache[fseventsJs]
      var config = require('lighter-config')
      var changed
      mock(config, {
        lighterRun: {
          ignore: '/IGNORE.txt'
        }
      })
      mock(console, {
        log: noop
      })
      mock(cp, {
        spawn: function (node, args) {
          return {
            on: noop,
            stdout: fakeStream,
            stderr: fakeStream,
            stdin: {
              write: function () {
                is.fail('Should have ignored IGNORE.txt')
              }
            }
          }
        }
      })
      mock(fsevents, {
        exports: function () {
          return {
            on: function (type, fn) {
              changed = fn
            },
            start: noop
          }
        }
      })
      delete cache[runJs]
      require('../run')
      changed(cwd + '/IGNORE.txt', {
        path: cwd + '/IGNORE.txt',
        event: 'created'
      })
      setTimeout(function () {
        unmock(config)
        unmock(console)
        unmock(cp)
        unmock(fsevents)
        done()
      }, 9)
    })

    it('falls back to fs.watch', function (done) {
      var fs = require('fs')
      var fsevents = cache[fseventsJs]
      mock(console, {
        log: mock.count()
      })
      mock(cp, {
        spawn: function () {
          return {
            on: noop,
            stdout: fakeStream,
            stderr: fakeStream,
            stdin: fakeStream,
            kill: function () {
              is(console.log.value, 1)
              unmock(console)
              unmock(cp)
              unmock(fsevents)
              unmock(fs)
              done()
            }
          }
        }
      })
      mock(fsevents, {
        exports: function () {
          throw new Error('fsevents only works on OSX.')
        }
      })
      mock(fs, {
        watch: function (dir, fn) {
          is(dir, cwd)
          setTimeout(function () {
            fn('change', cwd + '/restart.js')
          }, 1)
        }
      })
      delete cache[runJs]
      require('../run')
    })
  })
}

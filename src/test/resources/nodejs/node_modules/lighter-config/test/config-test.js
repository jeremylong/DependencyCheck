'use strict'
/* global describe it */
var is = global.is || require('exam/lib/is')
var mock = global.mock || require('exam/lib/mock')
var unmock = mock.unmock
var fs = require('fs')
var cwd = process.cwd()

var libPath = cwd + '/lighter-config.js'
var libContent = fs.readFileSync(libPath)

process.env = {}

describe('lighter-config', function () {
  it('is an object', function () {
    var config = getConfig()
    is.object(config)
  })

  describe('.get', function () {
    it('is a function', function () {
      var config = require(libPath)
      is.function(config.get)
    })

    it('is idempotent when used with no options', function () {
      var a = getConfig()
      var b = a.get()
      is.same(a, b)
    })

    describe('replacement', function () {
      it('sees an empty environment as staging', function () {
        var config = getConfig('')
        is(config.env, 'staging')
        is(config.environment, 'staging')
      })

      it('sees "whatever" as staging', function () {
        var config = getConfig('whatever')
        is(config.env, 'whatever')
        is(config.environment, 'staging')
      })

      it('sees "dev" as development', function () {
        var config = getConfig('dev')
        is(config.environment, 'development')
        is.false(config.isDebug)
        is.true(config.isDevelopment)
        is.false(config.isStaging)
        is.false(config.isProduction)
      })

      it('sees "debug" as development with debugging', function () {
        mock(console, {
          error: mock.count()
        })
        var config = getConfig('debug')
        is(console.error.value, 2)
        is(config.env, 'debug')
        is(config.environment, 'development')
        is.true(config.isDebug)
        is.true(config.isDevelopment)
        is.false(config.isStaging)
        is.false(config.isProduction)
      })

      it('sees "sandbox" as development', function () {
        var config = getConfig('sandbox')
        is(config.environment, 'development')
      })

      it('sees "alpha" as development', function () {
        var config = getConfig('alpha')
        is(config.environment, 'development')
      })

      it('sees "local" as development', function () {
        var config = getConfig('local')
        is(config.environment, 'development')
      })

      it('sees "development" as development', function () {
        var config = getConfig('development')
        is(config.environment, 'development')
      })

      it('sees "stage" as staging', function () {
        var config = getConfig('stage')
        is(config.environment, 'staging')
        is.false(config.isDebug)
        is.false(config.isDevelopment)
        is.true(config.isStaging)
        is.false(config.isProduction)
      })

      it('sees "qa" as staging', function () {
        var config = getConfig('qa')
        is(config.environment, 'staging')
      })

      it('sees "test" as staging', function () {
        var config = getConfig('test')
        is(config.environment, 'staging')
      })

      it('sees "beta" as staging', function () {
        var config = getConfig('beta')
        is(config.environment, 'staging')
      })

      it('sees "ci" as staging', function () {
        var config = getConfig('ci')
        is(config.environment, 'staging')
      })

      it('sees "jenkins" as staging', function () {
        var config = getConfig('jenkins')
        is(config.environment, 'staging')
      })

      it('sees "staging" as staging', function () {
        var config = getConfig('staging')
        is(config.environment, 'staging')
      })

      it('sees "prod" as production', function () {
        var config = getConfig('prod')
        is(config.environment, 'production')
        is.false(config.isDebug)
        is.false(config.isDevelopment)
        is.false(config.isStaging)
        is.true(config.isProduction)
      })

      it('sees "gamma" as production', function () {
        var config = getConfig('gamma')
        is(config.environment, 'production')
      })

      it('sees "release" as production', function () {
        var config = getConfig('release')
        is(config.environment, 'production')
      })

      it('sees "onebox" as production', function () {
        var config = getConfig('onebox')
        is(config.environment, 'production')
      })

      it('sees "canary" as production', function () {
        var config = getConfig('canary')
        is(config.environment, 'production')
      })

      it('sees "production" as production', function () {
        var config = getConfig('production')
        is(config.environment, 'production')
      })
    })

    describe('file reader', function () {
      it('reads config values', function () {
        mockFiles({
          base: {key: 'value'}
        })
        var config = getConfig()
        is(config.key, 'value')
        unmock()
      })

      it('replaces environment values', function () {
        mock(process.env, {
          KEY: 'VALUE'
        })
        mockFiles({
          base: {key: '$KEY'}
        })
        var config = getConfig()
        is(config.key, 'VALUE')
        unmock()
      })

      it('replaces empty environment values with empty strings', function () {
        mockFiles({
          base: {key: '$I_DO_NOT_EXIST'}
        })
        var config = getConfig()
        is(config.key, '')
        unmock()
      })

      it('replaces empty environment values with default strings', function () {
        mock(process.env, {
          PORT: 8888
        })
        mockFiles({
          base: {
            host: '${HOST-localhost}',
            port: '${PORT-8080}',
            suffix: '${SUFFIX-}'
          }
        })
        var config = getConfig()
        is(config.host, 'localhost')
        is(config.port, '8888')
        is(config.suffix, '')
        unmock()
      })

      it('logs an error when JSON is invalid', function () {
        var fs = {}
        fs[cwd + '/config/base.json'] = 'this is not valid JSON'
        fs[libPath] = libContent
        mock.fs(fs)
        mock(console, {
          error: mock.count()
        })
        var config = getConfig()
        is(console.error.value, 1)
        is(config.environment, 'staging')
        unmock()
      })

      it('reads sub-environment values', function () {
        mockFiles({
          base: {me: 'b'},
          production: {me: 'p', subEnvironments: ['pre-production']},
          'pre-production': {me: 'pp'}
        })
        var prod = getConfig('production')
        is(prod.me, 'p')
        var preprod = getConfig('pre-production')
        is(preprod.me, 'pp')
        unmock()
      })
    })
  })

  describe('.load', function () {
    it('decorates deeply', function () {
      mockFiles({
        base: {stuff: {something: 'this'}},
        staging: {stuff: {something: 'that'}}
      })
      var config = getConfig()
      is(config.stuff.something, 'that')
      unmock()
    })
  })
})

function getConfig (env) {
  process.env.ENV = env
  var cache = require.cache
  for (var path in cache) {
    if (/lighter-config/.test(path)) {
      delete cache[path]
    }
  }
  return require('../lighter-config')
}

function mockFiles (map) {
  var fs = {}
  var dir = fs[cwd + '/config'] = {}
  for (var key in map) {
    dir[key + '.json'] = JSON.stringify(map[key])
  }
  fs[libPath] = libContent
  mock.fs(fs)
}

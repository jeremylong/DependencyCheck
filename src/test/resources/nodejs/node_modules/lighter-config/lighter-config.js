'use strict'
var fs = require('fs')
var pe = process.env
var map = {d: 'development', s: 'staging', p: 'production'}
var found = {
  dir: pe.CONFIG_DIR,
  env: pe.NODE_ENV || pe.LIGHTER_ENV || pe.DEPLOY_ENV || pe.ENV,
  base: pe.CONFIG_BASE
}

// Create the hidden "get" property.
hide(exports, 'get', get)

// Get a configuration based on environment variables.
exports.get(found, exports)

/**
 * Get a configuration based on options.
 *
 * @param  {Object} options  An optional object with optional parameters:
 *                           - dir: defaults to "config".
 *                           - env: defaults to "staging".
 *                           - base: defaults to "base".
 * @param  {Object} config   An optional object to populate.
 * @return {Object}          A fully populated configuration object.
 */
function get (options, config) {
  options = options || found
  config = config || {}

  // Load options.
  var dir = options.dir || found.dir || 'config'
  var env = options.env || found.env || 'staging'
  var base = options.base || found.base || 'base'

  // Allow many "env" values.
  var key = env.toLowerCase()
    .replace(/^([gro]|ca)/, 'p')  // gamma, release, one, canary -> "production".
    .replace(/^(sa|[al])/, 'd')   // sandbox, alpha, local -> "development".
    .replace(/^[qtbcij]/, 's')[0] // qa, test, beta, ci, jenkins -> "staging".

  // Coerce to an expected environment.
  var environment = map[key] || map[key = 's']

  config.env = env
  config.environment = environment
  config.isDebug = /de?bu?g/i.test(env)
  config.isDevelopment = (key === 'd')
  config.isStaging = (key === 's')
  config.isProduction = (key === 'p')

  // Load files.
  hide(config, 'load', load)

  // Load configuration from files.
  config.load(dir, base)
  config.load(dir, environment)

  // Load any matching sub-environments.
  var subEnvironments = config.subEnvironments
  if (subEnvironments && subEnvironments.indexOf(env) > -1) {
    config.load(dir, env)
  }

  return config
}

/**
 * Load a configuration file from the /config directory, and decorate the
 * module exports with its values.
 *
 * @param  {String} name  File name, excluding ".json"
 */
function load (dir, name) {
  // Read config JSON.
  var path = dir + '/' + name + '.json'
  var json
  try {
    json = '' + fs.readFileSync(path)
  } catch (error) {
    if (this.isDebug) {
      console.error('No configuration found in "' + path + '".', error)
    }
    return
  }

  // Replace tokens like $HOST and ${PORT-8080} with environment variables.
  json = json.replace(/\$(\w+)/g, function (match, key) {
    return pe[key] || ''
  }).replace(/\$\{(\w+)(-[^\}]*)?\}/g, function (match, key, value) {
    return pe[key] || value.substr(1)
  })

  // Parse and decorate.
  try {
    var config = JSON.parse(json)
    decorate(this, config)
  } catch (error) {
    return console.error('Invalid JSON in "' + path + '".', json, error)
  }
}

/**
 * Decorate one configuration object with values from another.
 *
 * @param  {Object} object  An existing config object.
 * @param  {Object} values  An overriding config object.
 */
function decorate (object, values) {
  for (var key in values) {
    if (typeof object[key] === 'object') {
      decorate(object[key], values[key])
    } else {
      object[key] = values[key]
    }
  }
}

/**
 * Set a non-enumerable property value.
 *
 * @param  {Object} object  An object.
 * @param  {Object} name    A property name.
 * @param  {Object} value   A property value.
 */
function hide (object, name, value) {
  Object.defineProperty(object, name, {
    enumerable: false,
    value: value
  })
}

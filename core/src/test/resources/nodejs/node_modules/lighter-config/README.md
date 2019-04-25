# lighter-config
[![Chat](https://badges.gitter.im/chat.svg)](//gitter.im/lighterio/public)
[![Version](https://img.shields.io/npm/v/lighter-config.svg)](//www.npmjs.com/package/lighter-config)
[![Downloads](https://img.shields.io/npm/dm/lighter-config.svg)](//www.npmjs.com/package/lighter-config)
[![Build](https://img.shields.io/travis/lighterio/lighter-config.svg)](//travis-ci.org/lighterio/lighter-config)
[![Coverage](https://img.shields.io/coveralls/lighterio/lighter-config/master.svg)](//coveralls.io/r/lighterio/lighter-config)
[![Style](https://img.shields.io/badge/code%20style-standard-brightgreen.svg)](//www.npmjs.com/package/standard)

The `lighter-config` module loads configuration files and allows JSON to be
decorated with environment variables for `"development"`, `"staging"` and
`"production"` environments, according to the `NODE_ENV`, `LIGHTER_ENV`,
`DEPLOY_ENV` or `ENV` environment variables.

## Installation
From your project directory, install and save as a dependency:
```bash
npm install --save lighter-config
```

## Usage
Create the following files in your project directory, with some JSON content:
* `/config/base.json`
* `/config/development.json`
* `/config/staging.json`
* `/config/production.json`

Then in your project, from a file such as `/index.js`, require the
`lighter-config` module, and use the result as your configuration.

```js
var config = require('lighter-config')

// Example usage of config:
if (config.isDevelopment) {
  console.log('Currently running in development mode.')

  // And if base.json or development.json has a "host" and "port" property:
  console.log('Listening at http://' + config.host + ':' + config.port)
}
```

## Configuration Result
The result of requiring `lighter-config` is an object with the following
base properties, as well as any properties found in configuration files:

* (String) `config.env`
* (String) `config.environment`
* (Boolean) `config.isDebug`
* (Boolean) `config.isDevelopment`
* (Boolean) `config.isStaging`
* (Boolean) `config.isProduction`
* (Function) `config.get(options)`
* (Function) `config.load(dir, name)`

### `config.env`
The `env` is found from an environment variable, as described below, or from
the `env` property of the options argument to the `get` method as described
below. If omitted, it defaults to "staging".

### `config.environment`
The `environment` is based on the `env`, and is coerced to be either
"development", "staging" or "production".

### `config.isDebug`
The `isDebug` property is a special property which is true if the `env` is
something like "debug" or "dbg".

### `config.isDevelopment`, `config.isStaging` and `config.isProduction`
The `isDevelopment`, `isStaging` and `isProduction` properties are based on the
`environment`. Exactly one of them is `true`.

### `config.get(options)`
The `lighter-config` library returns an object which can be used to load other
configurations using the `get` method. The options object can have the
following properties:
* `env` determines the `config.env` value (with the default being "staging").
* `dir` determines which directory JSON files will be loaded from (with the
  default being "config"). The value is used to prefix calls to
  `fs.readFileSync`, so it can be an absolute path.
* `base` determines the name of the base configuration, such as `base.json`,
  which is loaded prior to the environment-specific configuration, such as
  `staging.json`. It defaults to "base", making the base configuration file
  `base.json`.

Example:
```js
var config = require('lighter-config')
var prodConfig = config.get({env: 'production'})
```

### `config.load(dir, name)`
The `load` method can load a named configuration from a directory, and use it
to override a configuration object's properties.

### `config.subEnvironments`
If a configuration file contains a key called `subEnvironments` with an array
of sub-environment names, then those environment names are whitelisted as
override files.

Example `production.json`:
```js
{
  "key": "p",
  "subEnvironments": ["pre-production"]
}
```

Example `pre-production.json`:
```js
{
  "key": "pp"
}
```
If the `NODE_ENV` is set to "pre-production", then the "pre-production.json"
file will be loaded and used to override the "production.json" configuration.


## Environment Variables
You can affect the outcome of `lighter-config` by running your application with
specific environment variable values, or modifying `process.env` prior to
requiring `lighter-config`.

### `CONFIG_DIR`
Determines where `lighter-config` will look for configuration JSON files.
Defaults to "config" if not found.

### `CONFIG_BASE`
Determines the name of the base configuration. Defaults to "base".

### `NODE_ENV`, `LIGHTER_ENV`, `DEPLOY_ENV` or `ENV`
Determines the value of `config.env` directly, and `config.environment`
indirectly. Defaults to "staging" if not found.

## Replacements
Configuration files can include replacement variables, for which substitutions
will be made. For example, if you want to expect a host and port to be in the
`HOST` and `PORT` environment variables, you can provide the following JSON:
```json
{
  "host": "$HOST",
  "port": "$PORT"
}
```

You can also include default values:
```json
{
  "host": "${HOST-localhost}",
  "port": "${PORT-1337}"
}
```

## More on lighter-config...
* [Contributing](//github.com/lighterio/lighter-config/blob/master/CONTRIBUTING.md)
* [License (ISC)](//github.com/lighterio/lighter-config/blob/master/LICENSE.md)
* [Change Log](//github.com/lighterio/lighter-config/blob/master/CHANGELOG.md)
* [Roadmap](//github.com/lighterio/lighter-config/blob/master/ROADMAP.md)

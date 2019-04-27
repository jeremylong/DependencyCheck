#!/usr/bin/env node

var spawn = require('child_process').spawn
var config = require('lighter-config').lighterRun || {}
var stdout = process.stdout
var write = stdout.write
var node = process.execPath
var argv = process.argv
var cwd = process.cwd()
var env = process.env
var child = null
var output = ''
var previousStart = 0
var failureOutput

// Try to restart in half a second.
var minRestartDelay = config.minRestartDelay || 500

// Wait 5 seconds at most.
var maxRestartDelay = config.maxRestartDelay || 5000

// Wait twice as long each time.
var restartDelayBackoff = config.restartDelayBackoff || 2

// Call a restart "ok" after 2 seconds without failing.
var cleanTime = config.cleanTime || 2000

// The first time we restart, do it quickly.
var restartDelay = 0

// Directories to watch.
var watchDirs = config.watchDirs || [cwd]

// Globs for paths whose changes should be ignored.
var ignore = globify(config.ignore || ['.DS_Store', '.cache', '.git', '.idea', '.project', 'coverage', 'data', 'log'])

// Globs for paths whose changes are live-reloadable.
var live = globify(config.live || ['public', 'scripts', 'styles', 'views'])

/**
 * Treat a single string or a falsy value as a string array.
 *
 * @param  {String|Array} value  A string or an array of strings.
 * @return {Array}               An array of RegExp patterns.
 */
function globify (value) {
  var array = typeof value === 'string' ? [value] : value
  array.forEach(function (pattern, index) {
    pattern = pattern
      .replace(/([\W])/g, function (c) {
        switch (c) {
          case '*': return '.+'
          default: return '\\' + c
        }
      })
    if (pattern.substr(0, 2) === '\\\/') {
      pattern = '^' + pattern.substr(2)
    } else {
      pattern = '(^|\\/)' + pattern
    }
    array[index] = pattern + '($|\\/)'
  })
  var pattern = '(' + array.join('|') + ')'
  pattern = new RegExp(pattern, 'i')
  return pattern
}

// Watch for changes.
watchDirs.forEach(function (dir) {
  var fsevents
  try {
    fsevents = require('fsevents')
    var watcher = fsevents(dir)
    watcher.on('change', changed)
    watcher.start()
  } catch (e) {
    var fs = require('fs')
    fs.watch(dir, function (type, path) {
      changed(path, {event: type, path: path})
    })
  }
})

// Find arguments that come before or after a double-dash.
var dashes = argv.indexOf('--')
var args = dashes < 0 ? argv : argv.slice(0, dashes)
var childArgs = dashes < 0 ? [] : argv.slice(dashes + 1)

// Find the specified file, or default to "main" from "package.json".
try {
  var file = args[2] || require.resolve(cwd)
  childArgs.unshift(file)
} catch (e) {
  console.error('The current directory does not have a node application.\n' +
    'Please use "npm init", then create an entry point file such as "index.js".')
  process.exit()
}

// Start the application!
start()

/**
 * Respond to a change event.
 *
 * @param  {String} path  Path of the file in which the change occurred.
 * @param  {Object} info  Information about the change from `fsevents`.
 */
function changed (path, info) {
  // Get a relative path.
  if (path.indexOf(cwd + '/') === 0) {
    path = path.slice(cwd.length + 1)
  }
  // If not ignored, we'll at least log the change.
  if (!ignore.test(path)) {
    var data = info.event
    data = data[0].toUpperCase() + data.substr(1) + ' "' + path +
      '"\u001b[90m at ' + (new Date()).toTimeString() + '\u001b[39m'
    if (!child.killed) {
      if (live.test(path)) {
        console.log('\u001b[32m' + data)
        info = JSON.stringify(info)
        child.stdin.write(info + '\n')
      } else {
        console.log('\u001b[33m' + data + '\n')
        child.kill()
      }
    }
  }
}

/**
 * Get a string of numberless ordered lines for deduping logs.
 *
 * @param  {String} text  Text received from the child's stdout.
 * @return {String}       Numberless ordered lines.
 */
function munge (text) {
  var lines = ('' + text).split('\n')
  lines.forEach(function (line, index) {
    lines[index] = lines[index].replace(/\d+/, '#')
  })
  lines.sort()
  text = lines.join('\n').trim()
  return text
}

/**
 * Start an application.
 */
function start () {
  var now = Date.now()
  var elapsed = now - previousStart

  // If it's been a while since we restarted, call this a clean start.
  var isCleanStart = elapsed >= cleanTime
  previousStart = now

  // Spawn the child process, and pipe output to stdout.
  child = spawn(node, childArgs, {cwd: cwd, env: env})
  child.stdout.pipe(stdout)
  child.stderr.pipe(stdout)

  // When we've started cleanly, pipe child process output directly to stdout.
  if (isCleanStart) {
    restartDelay = 0

  // After a fast failure, buffer the output in case we fail again.
  } else {
    stdout.write = function (chunk) {
      output += chunk
    }

    // When we've started cleanly, write output to stdout and start piping.
    this.cleanTimer = setTimeout(function () {
      stdout.write = write
      stdout.write(output)
      output = ''
      restartDelay = 0
    }, cleanTime)
  }

  // When a child process dies, restart it.
  child.on('close', function () {
    // Restore stdout.write
    stdout.write = write

    // If we failed differently, log the new output.
    if (failureOutput && (munge(output) !== munge(failureOutput))) {
      stdout.write('\n' + output)

    // If we failed the same way, just show another red dot.
    } else if (!child.killed) {
      stdout.write('\u001b[31m.\u001b[39m')
    }
    failureOutput = output
    output = ''
    clearTimeout(this.cleanTimer)
    this.cleanTimer = setTimeout(start, restartDelay)
    restartDelay = Math.min(restartDelay * restartDelayBackoff, maxRestartDelay) || minRestartDelay
  })
}

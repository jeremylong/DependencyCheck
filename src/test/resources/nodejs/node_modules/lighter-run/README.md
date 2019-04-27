# lighter-run
[![Chat](https://badges.gitter.im/chat.svg)](//gitter.im/lighterio/public)
[![Version](https://img.shields.io/npm/v/lighter-run.svg)](//www.npmjs.com/package/lighter-run)
[![Downloads](https://img.shields.io/npm/dm/lighter-run.svg)](//www.npmjs.com/package/lighter-run)
[![Build](https://img.shields.io/travis/lighterio/lighter-run.svg)](//travis-ci.org/lighterio/lighter-run)
[![Coverage](https://img.shields.io/codecov/c/github/lighterio/lighter-run/master.svg)](//codecov.io/gh/lighterio/lighter-run)
[![Style](https://img.shields.io/badge/code%20style-standard-brightgreen.svg)](//www.npmjs.com/package/standard)

With `lighter-run`, you can run the node application that's in your current
directory, and it will restart when files change.

## Quick Start
1. Install globally (using sudo if necessary).
```bash
npm install --global lighter-run
```
2. Ensure that the `"main"` property in your `package.json` points to your
application's entry point file.

3. Run!
```bash
lighter-run
```

## Passing Arguments

To pass arguments to your entry point, just list them after a double-dash:

```bash
lighter-run -- ARG1 ARG2 ARG3
```

## Running Other Files

If you'd like to run a file other than the one that's specified as `"main"` in
your `package.json`, then you can specify it as an argument to `lighter-run`:

```bash
lighter-run index
```

**NOTE:** You can omit the ".js" extension just as you would with the `node`
executable.


## Configuration
`lighter-run` uses `lighter-config` for its configuration. Just create a
`"config/base.json"` file in your project, and add some options under a
property called `"lighterRun"`. The following is an example of a configuration
which uses the default values:
```json
{
  "lighterRun": {
    "minRestartDelay": 500,
    "maxRestartDelay": 5000,
    "restartDelayBackoff": 2,
    "cleanTime": 2000,
    "ignore": [
      ".DS_Store",
      ".cache",
      ".git",
      ".idea",
      ".project",
      "coverage",
      "data",
      "log"
    ],
    "live": [
      "public",
      "scripts",
      "styles",
      "views"
    ],
    "watchDirs": null
  }
}
```

**minRestartDelay**<br>
Amount of time to wait before trying to restart (the first time).

**maxRestartDelay**<br>
Maximum amount of time to wait before trying to restart, after failing many times.

**restartDelayBackoff**<br>
Multiplier to be applied to the restart delay time after each failure.

**cleanTime**<br>
Length of time that a process must be running before it's considered to have started cleanly.

**ignore**<br>
File patterns in which changes should be ignored.

**live**<br>
File patterns that can be live-reloaded instead of restarting the process.

**watchDirs**<br>
Absolute paths for directories that should be watched. (Defaults to the current
working directory).


## More on lighter-run...
* [Contributing](//github.com/lighterio/lighter-run/blob/master/CONTRIBUTING.md)
* [License (ISC)](//github.com/lighterio/lighter-run/blob/master/LICENSE.md)
* [Change Log](//github.com/lighterio/lighter-run/blob/master/CHANGELOG.md)
* [Roadmap](//github.com/lighterio/lighter-run/blob/master/ROADMAP.md)

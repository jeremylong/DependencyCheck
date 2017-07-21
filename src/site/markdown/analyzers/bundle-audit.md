Ruby Bundle-audit Analyzer
=====================

OWASP dependency-check includes an analyzer that will execute [bundle-audit](https://github.com/rubysec/bundler-audit#readme)
and include the results in the dependency-check report. This is useful for multi-language
projects and merging the results of multiple software composition analysis tools.

```shell
$ sudo gem install bundler-audit
$ bundle-audit update
```

Files Types Scanned: Gemfile.lock

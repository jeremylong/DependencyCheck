Composer Lock Analyzer
==============

OWASP dependency-check includes an analyzer that scans composer.lock files to get exact dependency
version information from PHP projects which are managed with [Composer](http://getcomposer.org/).
If you're using Composer to manage your project, this will only analyze the `composer.lock` file
currently, so you'll need to run `composer install` to have Composer generate this file.

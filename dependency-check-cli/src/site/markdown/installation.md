Installation & Usage
--------------------
Downlod the dependency-check command line tool [here](http://dl.bintray.com/jeremy-long/owasp/dependency-check-1.0.0-release.zip).
Extract the zip file to a location on your computer and put the 'bin' directory into the
path environment variable. On \*nix systems you will likely need to make the shell
script executable:

    $ chmod +777 dependency-check.sh

To scan a folder on the system you can run:

### Windows
    dependency-check.bat --app "My App Name" --scan "c:\java\application\lib"

### \*nix
    dependency-check.sh --app "My App Name" --scan "/java/application/lib"
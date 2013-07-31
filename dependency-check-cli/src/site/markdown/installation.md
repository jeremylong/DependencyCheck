Installation & Usage
--------------------
The dependency-check command line utility can be downloaded from bintray. Extract
the zip file to a location on your computer and put the 'bin' directory into the
path environment variable. On \*nix systems you will likely need to make the shell
script executable:

    $ chmod +777 dependency-check.sh

To scan a folder on the system you can run:

### Windows
    dependency-check.bat --app "My App Name" --scan "c:\java\application\lib"

### \*nix
    dependency-check.sh --app "My App Name" --scan "/java/application/lib"
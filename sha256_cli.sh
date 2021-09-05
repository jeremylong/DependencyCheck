#/bin/bash

ver=$(curl -s https://jeremylong.github.io/DependencyCheck/current.txt)
echo "Version $ver"
wget -q https://github.com/jeremylong/DependencyCheck/releases/download/v$ver/dependency-check-$ver-release.zip 
shasum -a 256 dependency-check-$ver-release.zip
rm dependency-check-$ver-release.zip

#/bin/bash

ver=`curl -s https://jeremylong.github.io/DependencyCheck/current.txt`
echo "Version $ver"
curl -s https://github.com/jeremylong/DependencyCheck/releases/download/v4ver/dependency-check-$ver-release.zip | shasum -a 256

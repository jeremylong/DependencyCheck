#!/bin/bash -e

VERSION=$(mvn -q \
    -Dexec.executable="echo" \
    -Dexec.args='${project.version}' \
    --non-recursive \
    org.codehaus.mojo:exec-maven-plugin:1.3.1:exec)

if [[ $VERSION = *"SNAPSHOT"* ]]; then
  echo "Do not publish a snapshot version of dependency-check"
else
  FILE=./cli/target/dependency-check-$VERSION-release.zip
  if [ -f "$FILE" ]; then
    cd cli
    docker build . --build-arg VERSION=$VERSION -t owasp/dependency-check:$VERSION
    docker tag owasp/dependency-check:$VERSION owasp/dependency-check:latest
    docker push owasp/dependency-check:$VERSION 
    docker push owasp/dependency-check:latest
    cd ..
  else 
      echo "$FILE does not exist - run 'mvn package' first"
  fi


  
fi

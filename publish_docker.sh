#!/bin/bash -e

VERSION=$(mvn -q \
    -Dexec.executable="echo" \
    -Dexec.args='${project.version}' \
    --non-recursive \
    org.codehaus.mojo:exec-maven-plugin:1.3.1:exec)

if [[ $VERSION = *"SNAPSHOT"* ]]; then
  echo "Do not publish a snapshot version of dependency-check"
else
    cd cli
    mvn package
    mvn dockerfile:build
    mvn dockerfile:tag@tag-version
    mvn dockerfile:push@push-latest
    mvn dockerfile:push@push-version
    cd ..
fi

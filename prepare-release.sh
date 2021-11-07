#!/bin/bash -e

git checkout main
git pull

SNAPSHOT=$(mvn help:evaluate -Dexpression=project.version -q -DforceStdout)

RELEASE=$(echo $SNAPSHOT | sed s/-SNAPSHOT//)

git checkout -b "release-$RELEASE"

mvn release:prepare --no-transfer-progress --batch-mode
mvn release:clean --no-transfer-progress --batch-mode

git push origin "release-$RELEASE"

git checkout main

git branch -D "release-$RELEASE"
#!/bin/bash -e

git checkout main
git pull --rebase

SNAPSHOT=$(mvn help:evaluate -Dexpression=project.version -q -DforceStdout)
RELEASE=${SNAPSHOT/-SNAPSHOT/}

git checkout -b "release-$RELEASE"

mvn release:prepare --no-transfer-progress --batch-mode
mvn release:clean --no-transfer-progress --batch-mode

git push origin "release-$RELEASE"

git checkout main

git branch -D "release-$RELEASE"
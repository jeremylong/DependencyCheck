#!/bin/bash -e

version=$(curl -s https://jeremylong.github.io/DependencyCheck/current.txt)

docker image build -t owasp/dependency-check:${version} .
docker tag owasp/dependency-check:${version} owasp/dependency-check:latest
docker login
docker push owasp/dependency-check:${version}
docker push owasp/dependency-check:latest

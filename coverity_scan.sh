#!/bin/bash -e

if [ $TRAVIS_BRANCH = "master" ] && [ $TRAVIS_EVENT_TYPE = "cron" ] ; then
  echo "Executing Coverity Scan"
  
  export COVERITY_SCAN_PROJECT_NAME="jeremylong/DependencyCheck"
  export COVERITY_SCAN_NOTIFICATION_EMAIL="jeremy.long@owasp.org"
  export COVERITY_SCAN_BRANCH_PATTERN="master"
  export COVERITY_SCAN_BUILD_COMMAND="mvn package -Dmaven.test.skip=true"

  curl -s https://scan.coverity.com/scripts/travisci_build_coverity_scan.sh | bash
fi
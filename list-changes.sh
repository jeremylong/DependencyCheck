#!/bin/bash -e
##https://blogs.sap.com/2018/06/22/generating-release-notes-from-git-commit-messages-using-basic-shell-commands-gitgrep/
git --no-pager log $(git describe --tags --abbrev=0)..HEAD --pretty=format:" - %s" | grep -v ' - Bump'
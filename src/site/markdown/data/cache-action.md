GitHub Action
----------------

The following is an example of how one could cache the data directory using GitHub Actions.
Note that this configuration is setup for Maven but could be altered to support gradle or
even the CLI.

**WARNING** this configuration uses a single API key configured in secrets. If multiple actions
use the same API Key you could hit the NVD rate limits.


```yaml
name: Vulnerability Scan

on:
  pull_request:
  workflow_dispatch:

jobs:
  owasp-scan:
    if: github.actor != 'dependabot[bot]'
    runs-on: ubuntu-20.04
    steps:
      - uses: actions/checkout@v4

      - name: Set up JDK 17
        uses: actions/setup-java@v3
        with:
          java-version: 17
          distribution: 'adopt'
          server-id: github
          server-username: MAVEN_USERNAME
          server-password: MAVEN_PASSWORD
          cache: 'maven'
          
      - name: Get Date
        id: get-date
        run: |
          echo "datetime=$(/bin/date -u "+%Y%m%d%H")" >> $GITHUB_OUTPUT
        shell: bash

      - name: Restore cached Maven dependencies
        uses: actions/cache/restore@v3
        with:
          path: ~/.m2/repository
          # Using datetime in cache key as OWASP database may change, without the pom changing
          key: ${{ runner.os }}-maven-${{ steps.get-date.outputs.datetime }}-${{ hashFiles('**/pom.xml') }}
          restore-keys: |
            ${{ runner.os }}-maven-${{ steps.get-date.outputs.datetime }}
            ${{ runner.os }}-maven-
            
      - name: Build & scan
        id: scan
        run: |
          mvn --no-transfer-progress clean package -DskipTests -DnvdApiKey=${{secrets.nvdApiKey}} -DskipITs -Dmax.cvss.score=8 \
            org.owasp:dependency-check-maven:check -l ${{github.workspace}}/mvn-output.txt 
        env:
          MAVEN_USERNAME: ${{ secrets.MAVEN_USERNAME}}
          MAVEN_PASSWORD: ${{ secrets.MAVEN_PASSWORD}}
          
     - name: Cache Maven dependencies
        uses: actions/cache/save@v3
        if: always()
        with:
          path: ~/.m2/repository
          key: ${{ runner.os }}-maven-${{ steps.get-date.outputs.datetime }}-${{ hashFiles('**/pom.xml') }}
```
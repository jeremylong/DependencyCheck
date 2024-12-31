# Utilities for manual test scenario with an authenticating proxy

# Prerequisites

* A docker environment is available on the local machine
* A compatible unix/linux shell (at least `bash` and `zsh` should work)
* **NOTE:** The testing should also be possible on windows, but then the start command for the container would have to
  be adapted to properly map the configuration files into the squid-proxy container which is left as an exercise to the
  tester that wants to run it on windows.
* A working connection to internet from your docker runtime environment (squid-proxy would need to be able to reach the various internet resources ODC uses)

# Preparation

* Start the docker container running squid-proxy exposing the proxy to port 53128 by running the shellsceript
    ```shell
    ./start-docker-squid-proxy-with-auth
    ```
* Set JAVA_TOOL_OPTIONS to reflect the proxy just started
    ```shell
    export JAVA_TOOL_OPTIONS="-Dhttps.proxyHost=localhost -Dhttps.proxyPort=53128 -Dhttps.proxyUser=proxy -Dhttps.proxyPassword=insecure"
    ```

# Manual test execution

Run whichever integration of DependencyCheck to validate its proper working across an authenticating proxy from the same
shell (or make sure in a new shell that the same `JAVA_TOOL_OPTIONS` environment variable is active)

# Cleanup

* Stop the docker container running squid-proxy (due to start with --rm the container will be deleted upon termination)
    ```shell
    ./stop-docker-squid-proxy-with-auth
    ```
* Unset JAVA_TOOL_OPTIONS or set it back to your regular value
    ```shell
    export JAVA_TOOL_OPTIONS=
    ```
  or
    ```shell
    export JAVA_TOOL_OPTIONS=...your regular options...
    ```
  

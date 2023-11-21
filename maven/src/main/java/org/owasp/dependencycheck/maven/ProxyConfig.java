/*
 * This file is part of dependency-check-core.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) 2023 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.maven;

/**
 * Proxy configuration options.
 *
 * @author Jeremy Long
 */
public class ProxyConfig {

    /**
     * The proxy host.
     */
    private String host;
    /**
     * The proxy port.
     */
    private int port = 8080;
    /**
     * ID of server in Maven settings.xml, &lt;username&gt; and &lt;password&gt; will be
     * used.
     */
    private String serverId;

    /**
     * Get the host.
     *
     * @return the host
     */
    public String getHost() {
        return host;
    }

    /**
     * Set the host.
     *
     * @param host the new host
     */
    public void setHost(String host) {
        this.host = host;
    }

    /**
     * Get the port.
     *
     * @return the port
     */
    public int getPort() {
        return port;
    }

    /**
     * Set the new port number.
     *
     * @param port the port number
     */
    public void setPort(int port) {
        this.port = port;
    }

    /**
     * The server id.
     *
     * @return the server id
     */
    public String getServerId() {
        return serverId;
    }

    /**
     * Sets the server id.
     *
     * @param serverId the new server id
     */
    public void setServerId(String serverId) {
        this.serverId = serverId;
    }

}

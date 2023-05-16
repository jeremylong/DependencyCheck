package org.owasp.dependencycheck.maven;

/**
 * Proxy configuration options.
 */
public class ProxyConfig {

	String host;
	
	int port = 8080;
	
	/**
	 * ID od server in Maven settings.xml, <username> and <password> will be used.
	 */
	String serverId;

}

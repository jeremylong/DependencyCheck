package org.owasp.dependencycheck.utils;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class is used to enable additional ciphers used by the SSL Socket. This
 * is specifically because the NVD stopped supporting TLS 1.0 and Java 6 and 7
 * clients by default were unable to connect to download the NVD data feeds.
 *
 * The following code was copied from
 * http://stackoverflow.com/questions/1037590/which-cipher-suites-to-enable-for-ssl-socket/23365536#23365536
 *
 * @author <a href="http://stackoverflow.com/users/608639/jww">jww</a>
 */
public class SSLSocketFactoryEx extends SSLSocketFactory {

    /**
     * The Logger for use throughout the class.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(SSLSocketFactoryEx.class);

    /**
     * Constructs a new SSLSocketFactory.
     *
     * @throws NoSuchAlgorithmException thrown when an algorithm is not
     * supported
     * @throws KeyManagementException thrown if initialization fails
     */
    public SSLSocketFactoryEx() throws NoSuchAlgorithmException, KeyManagementException {
        initSSLSocketFactoryEx(null, null, null);
    }

    /**
     * Constructs a new SSLSocketFactory.
     *
     * @param km the key manager
     * @param tm the trust manager
     * @param random secure random
     * @throws NoSuchAlgorithmException thrown when an algorithm is not
     * supported
     * @throws KeyManagementException thrown if initialization fails
     */
    public SSLSocketFactoryEx(KeyManager[] km, TrustManager[] tm, SecureRandom random) throws NoSuchAlgorithmException, KeyManagementException {
        initSSLSocketFactoryEx(km, tm, random);
    }

    /**
     * Constructs a new SSLSocketFactory.
     *
     * @param ctx the SSL context
     * @throws NoSuchAlgorithmException thrown when an algorithm is not
     * supported
     * @throws KeyManagementException thrown if initialization fails
     */
    public SSLSocketFactoryEx(SSLContext ctx) throws NoSuchAlgorithmException, KeyManagementException {
        initSSLSocketFactoryEx(ctx);
    }

    /**
     * Returns the default cipher suites.
     *
     * @return the default cipher suites
     */
    @Override
    public String[] getDefaultCipherSuites() {
        return Arrays.copyOf(ciphers, ciphers.length);
    }

    /**
     * Returns the supported cipher suites.
     *
     * @return the supported cipher suites
     */
    @Override
    public String[] getSupportedCipherSuites() {
        return Arrays.copyOf(ciphers, ciphers.length);
    }

    /**
     * Returns the default protocols.
     *
     * @return the default protocols
     */
    public String[] getDefaultProtocols() {
        return Arrays.copyOf(protocols, protocols.length);
    }

    /**
     * Returns the supported protocols.
     *
     * @return the supported protocols
     */
    public String[] getSupportedProtocols() {
        return Arrays.copyOf(protocols, protocols.length);
    }

    /**
     * Creates an SSL Socket.
     *
     * @param s the base socket
     * @param host the host
     * @param port the port
     * @param autoClose if the socket should auto-close
     * @return the SSL Socket
     * @throws IOException thrown if the creation fails
     */
    @Override
    public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
        final SSLSocketFactory factory = sslCtxt.getSocketFactory();
        final SSLSocket ss = (SSLSocket) factory.createSocket(s, host, port, autoClose);

        ss.setEnabledProtocols(protocols);
        ss.setEnabledCipherSuites(ciphers);

        return ss;
    }

    /**
     * Creates a new SSL Socket.
     *
     * @param address the address to connect to
     * @param port the port number
     * @param localAddress the local address
     * @param localPort the local port
     * @return the SSL Socket
     * @throws IOException thrown if the creation fails
     */
    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
        final SSLSocketFactory factory = sslCtxt.getSocketFactory();
        final SSLSocket ss = (SSLSocket) factory.createSocket(address, port, localAddress, localPort);

        ss.setEnabledProtocols(protocols);
        ss.setEnabledCipherSuites(ciphers);

        return ss;
    }

    /**
     * Creates a new SSL Socket.
     *
     * @param host the host to connect to
     * @param port the port to connect to
     * @param localHost the local host
     * @param localPort the local port
     * @return the SSL Socket
     * @throws IOException thrown if the creation fails
     */
    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException {
        final SSLSocketFactory factory = sslCtxt.getSocketFactory();
        final SSLSocket ss = (SSLSocket) factory.createSocket(host, port, localHost, localPort);

        ss.setEnabledProtocols(protocols);
        ss.setEnabledCipherSuites(ciphers);

        return ss;
    }

    /**
     * Creates a new SSL Socket.
     *
     * @param host the host to connect to
     * @param port the port to connect to
     * @return the SSL Socket
     * @throws IOException thrown if the creation fails
     */
    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException {
        final SSLSocketFactory factory = sslCtxt.getSocketFactory();
        final SSLSocket ss = (SSLSocket) factory.createSocket(host, port);

        ss.setEnabledProtocols(protocols);
        ss.setEnabledCipherSuites(ciphers);

        return ss;
    }

    /**
     * Creates a new SSL Socket.
     *
     * @param host the host to connect to
     * @param port the port to connect to
     * @return the SSL Socket
     * @throws IOException thrown if the creation fails
     */
    @Override
    public Socket createSocket(String host, int port) throws IOException {
        final SSLSocketFactory factory = sslCtxt.getSocketFactory();
        final SSLSocket ss = (SSLSocket) factory.createSocket(host, port);

        ss.setEnabledProtocols(protocols);
        ss.setEnabledCipherSuites(ciphers);

        return ss;
    }

    /**
     * Initializes the SSL Socket Factory Extension.
     *
     * @param km the key managers
     * @param tm the trust managers
     * @param random the secure random number generator
     * @throws NoSuchAlgorithmException thrown when an algorithm is not
     * supported
     * @throws KeyManagementException thrown if initialization fails
     */
    private void initSSLSocketFactoryEx(KeyManager[] km, TrustManager[] tm, SecureRandom random)
            throws NoSuchAlgorithmException, KeyManagementException {
        sslCtxt = SSLContext.getInstance("TLS");
        sslCtxt.init(km, tm, random);

        protocols = getProtocolList();
        ciphers = getCipherList();
    }

    /**
     * Initializes the SSL Socket Factory Extension.
     *
     * @param ctx the SSL context
     * @throws NoSuchAlgorithmException thrown when an algorithm is not
     * supported
     * @throws KeyManagementException thrown if initialization fails
     */
    private void initSSLSocketFactoryEx(SSLContext ctx)
            throws NoSuchAlgorithmException, KeyManagementException {
        sslCtxt = ctx;

        protocols = getProtocolList();
        ciphers = getCipherList();
    }

    /**
     * Returns the protocol list.
     *
     * @return the protocol list
     */
    protected String[] getProtocolList() {
        final String[] preferredProtocols = {"TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"};
        String[] availableProtocols = null;

        SSLSocket socket = null;

        try {
            final SSLSocketFactory factory = sslCtxt.getSocketFactory();
            socket = (SSLSocket) factory.createSocket();

            availableProtocols = socket.getSupportedProtocols();
            Arrays.sort(availableProtocols);
        } catch (Exception ex) {
            LOGGER.debug("Error getting protocol list, using TLSv1", ex);
            return new String[]{"TLSv1"};
        } finally {
            if (socket != null) {
                try {
                    socket.close();
                } catch (IOException ex) {
                    LOGGER.trace("Error closing socket", ex);
                }
            }
        }

        final List<String> aa = new ArrayList<String>();
        for (String preferredProtocol : preferredProtocols) {
            final int idx = Arrays.binarySearch(availableProtocols, preferredProtocol);
            if (idx >= 0) {
                aa.add(preferredProtocol);
            }
        }

        return aa.toArray(new String[0]);
    }

    /**
     * Returns the cipher list.
     *
     * @return the cipher list
     */
    protected String[] getCipherList() {
        final String[] preferredCiphers = {
            // *_CHACHA20_POLY1305 are 3x to 4x faster than existing cipher suites.
            //   http://googleonlinesecurity.blogspot.com/2014/04/speeding-up-and-strengthening-https.html
            // Use them if available. Normative names can be found at (TLS spec depends on IPSec spec):
            //   http://tools.ietf.org/html/draft-nir-ipsecme-chacha20-poly1305-01
            //   http://tools.ietf.org/html/draft-mavrogiannopoulos-chacha-tls-02
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_SHA",
            "TLS_ECDHE_RSA_WITH_CHACHA20_SHA",
            "TLS_DHE_RSA_WITH_CHACHA20_POLY1305",
            "TLS_RSA_WITH_CHACHA20_POLY1305",
            "TLS_DHE_RSA_WITH_CHACHA20_SHA",
            "TLS_RSA_WITH_CHACHA20_SHA",
            // Done with bleeding edge, back to TLS v1.2 and below
            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
            // TLS v1.0 (with some SSLv3 interop)
            "TLS_DHE_RSA_WITH_AES_256_CBC_SHA384",
            "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
            "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
            "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
            "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
            "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
            "SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA",
            "SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA",
            // RSA key transport sucks, but they are needed as a fallback.
            // For example, microsoft.com fails under all versions of TLS
            // if they are not included. If only TLS 1.0 is available at
            // the client, then google.com will fail too. TLS v1.3 is
            // trying to deprecate them, so it will be interesteng to see
            // what happens.
            "TLS_RSA_WITH_AES_256_CBC_SHA256",
            "TLS_RSA_WITH_AES_256_CBC_SHA",
            "TLS_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_RSA_WITH_AES_128_CBC_SHA",};

        String[] availableCiphers;

        try {
            final SSLSocketFactory factory = sslCtxt.getSocketFactory();
            availableCiphers = factory.getSupportedCipherSuites();
            Arrays.sort(availableCiphers);
        } catch (Exception e) {
            LOGGER.debug("Error retrieving ciphers", e);
            return new String[]{
                "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
                "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
                "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
                "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
                "TLS_RSA_WITH_AES_256_CBC_SHA256",
                "TLS_RSA_WITH_AES_256_CBC_SHA",
                "TLS_RSA_WITH_AES_128_CBC_SHA256",
                "TLS_RSA_WITH_AES_128_CBC_SHA",
                "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",};
        }

        final List<String> aa = new ArrayList<String>();
        for (String preferredCipher : preferredCiphers) {
            final int idx = Arrays.binarySearch(availableCiphers, preferredCipher);
            if (idx >= 0) {
                aa.add(preferredCipher);
            }
        }

        aa.add("TLS_EMPTY_RENEGOTIATION_INFO_SCSV");

        return aa.toArray(new String[0]);
    }

    /**
     * The SSL context.
     */
    private SSLContext sslCtxt;
    /**
     * The cipher suites.
     */
    private String[] ciphers;
    /**
     * The protocols.
     */
    private String[] protocols;
}

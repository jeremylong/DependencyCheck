package org.owasp.dependencycheck.utils;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import org.apache.commons.lang3.StringUtils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * TODO - is this class needed anymore as we do not support Java 6 and 7.
 *
 * This class is used to enable additional ciphers used by the SSL Socket. This
 * is specifically because the NVD stopped supporting TLS 1.0 and Java 6 and 7
 * clients by default were unable to connect to download the NVD data feeds.
 * <p>
 * The following code was copied from
 * http://stackoverflow.com/questions/1037590/which-cipher-suites-to-enable-for-ssl-socket/23365536#23365536
 *
 * @author <a href="http://stackoverflow.com/users/608639/jww">jww</a>
 * @version $Id: $Id
 */
public class SSLSocketFactoryEx extends SSLSocketFactory {

    /**
     * The Logger for use throughout the class.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(SSLSocketFactoryEx.class);

    /**
     * The SSL context.
     */
    private SSLContext sslCtxt;
    /**
     * The protocols.
     */
    private String[] protocols;
    /**
     * The configured settings.
     */
    private final Settings settings;

    /**
     * Simple boolean flag to prevent logging the protocols repeatedly.
     */
    private static boolean protocolsLogged = false;

    /**
     * Constructs a new SSLSocketFactory.
     *
     * @param settings reference to the configured settings
     * @throws java.security.NoSuchAlgorithmException thrown when an algorithm
     * is not supported
     * @throws java.security.KeyManagementException thrown if initialization
     * fails
     */
    public SSLSocketFactoryEx(Settings settings) throws NoSuchAlgorithmException, KeyManagementException {
        this.settings = settings;
        final KeyManager[] km = getKeyManagers();
        final TrustManager[] tm = getTrustManagers();

        initSSLSocketFactoryEx(km, tm, null);
    }

    /**
     * Constructs a new SSLSocketFactory.
     *
     * @param km the key manager
     * @param tm the trust manager
     * @param random secure random
     * @param settings reference to the configured settings
     * @throws java.security.NoSuchAlgorithmException thrown when an algorithm
     * is not supported
     * @throws java.security.KeyManagementException thrown if initialization
     * fails
     */
    public SSLSocketFactoryEx(KeyManager[] km, TrustManager[] tm, SecureRandom random, Settings settings)
            throws NoSuchAlgorithmException, KeyManagementException {
        this.settings = settings;
        initSSLSocketFactoryEx(km, tm, random);
    }

    /**
     * Constructs a new SSLSocketFactory.
     *
     * @param ctx the SSL context
     * @param settings reference to the configured settings
     * @throws java.security.NoSuchAlgorithmException thrown when an algorithm
     * is not supported
     * @throws java.security.KeyManagementException thrown if initialization
     * fails
     */
    public SSLSocketFactoryEx(SSLContext ctx, Settings settings) throws NoSuchAlgorithmException, KeyManagementException {
        this.settings = settings;
        initSSLSocketFactoryEx(ctx);
    }

    /**
     * {@inheritDoc}
     * <p>
     * Returns the default cipher suites.
     */
    @Override
    public String[] getDefaultCipherSuites() {
        return sslCtxt.getSocketFactory().getDefaultCipherSuites();
    }

    /**
     * {@inheritDoc}
     * <p>
     * Returns the supported cipher suites.
     */
    @Override
    public String[] getSupportedCipherSuites() {
        return sslCtxt.getSocketFactory().getSupportedCipherSuites();
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
     * {@inheritDoc}
     * <p>
     * Creates an SSL Socket.
     */
    @Override
    public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
        final SSLSocketFactory factory = sslCtxt.getSocketFactory();
        final SSLSocket ss = (SSLSocket) factory.createSocket(s, host, port, autoClose);

        ss.setEnabledProtocols(protocols);

        return ss;
    }

    /**
     * {@inheritDoc}
     * <p>
     * Creates a new SSL Socket.
     */
    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
        final SSLSocketFactory factory = sslCtxt.getSocketFactory();
        final SSLSocket ss = (SSLSocket) factory.createSocket(address, port, localAddress, localPort);

        ss.setEnabledProtocols(protocols);

        return ss;
    }

    /**
     * {@inheritDoc}
     * <p>
     * Creates a new SSL Socket.
     */
    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException {
        final SSLSocketFactory factory = sslCtxt.getSocketFactory();
        final SSLSocket ss = (SSLSocket) factory.createSocket(host, port, localHost, localPort);

        ss.setEnabledProtocols(protocols);

        return ss;
    }

    /**
     * {@inheritDoc}
     * <p>
     * Creates a new SSL Socket.
     */
    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException {
        final SSLSocketFactory factory = sslCtxt.getSocketFactory();
        final SSLSocket ss = (SSLSocket) factory.createSocket(host, port);

        ss.setEnabledProtocols(protocols);

        return ss;
    }

    /**
     * {@inheritDoc}
     * <p>
     * Creates a new SSL Socket.
     */
    @Override
    public Socket createSocket(String host, int port) throws IOException {
        final SSLSocketFactory factory = sslCtxt.getSocketFactory();
        final SSLSocket ss = (SSLSocket) factory.createSocket(host, port);

        ss.setEnabledProtocols(protocols);

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
    }

    /**
     * Returns the protocol list.
     *
     * @return the protocol list
     */
    @SuppressWarnings("StringSplitter")
    protected String[] getProtocolList() {
        SSLSocket socket = null;
        final String[] availableProtocols;
        final String[] preferredProtocols = settings.getString(
                Settings.KEYS.DOWNLOADER_TLS_PROTOCOL_LIST,
                "TLSv1.1,TLSv1.2,TLSv1.3")
                .split(",");
        try {
            final SSLSocketFactory factory = sslCtxt.getSocketFactory();
            socket = (SSLSocket) factory.createSocket();

            availableProtocols = socket.getSupportedProtocols();
            Arrays.sort(availableProtocols);
            if (LOGGER.isDebugEnabled() && !protocolsLogged) {
                protocolsLogged = true;
                LOGGER.debug("Available Protocols:");
                for (String p : availableProtocols) {
                    LOGGER.debug(p);
                }
            }
        } catch (Exception ex) {
            LOGGER.debug("Error getting protocol list, using TLSv1.1-1.3", ex);
            return new String[]{"TLSv1.1", "TLSv1.2", "TLSv1.3"};
        } finally {
            if (socket != null) {
                try {
                    socket.close();
                } catch (IOException ex) {
                    LOGGER.trace("Error closing socket", ex);
                }
            }
        }

        final List<String> aa = new ArrayList<>();
        for (String preferredProtocol : preferredProtocols) {
            final int idx = Arrays.binarySearch(availableProtocols, preferredProtocol);
            if (idx >= 0) {
                aa.add(preferredProtocol);
            }
        }

        return aa.toArray(new String[0]);
    }

    private KeyManager[] getKeyManagers() {
        KeyManager[] km = null;
        final String ksPath = System.getProperty("javax.net.ssl.keyStore");
        final String ksType = System.getProperty("javax.net.ssl.keyStoreType");
        final String ksPass = System.getProperty("javax.net.ssl.keyStorePassword");

        if (!StringUtils.isAnyEmpty(ksPath, ksType, ksPass)) {
            try (FileInputStream fis = new FileInputStream(ksPath)) {
                final KeyStore ks = KeyStore.getInstance(ksType);
                ks.load(fis, ksPass.toCharArray());
                final KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
                kmf.init(ks, ksPass.toCharArray());
                km = kmf.getKeyManagers();
            } catch (KeyStoreException | IOException | CertificateException | UnrecoverableKeyException | NoSuchAlgorithmException ex) {
                throw new RuntimeException(ex);
            }
        }
        return km;
    }

    private TrustManager[] getTrustManagers() {
        TrustManager[] tm = null;
        final String ksType = System.getProperty("javax.net.ssl.keyStoreType");
        final String tsPath = System.getProperty("javax.net.ssl.trustStore");
        final String tsPass = System.getProperty("javax.net.ssl.trustStorePassword");

        if (!StringUtils.isAnyEmpty(tsPath, ksType, tsPass)) {
            try (FileInputStream fis = new FileInputStream(tsPath)) {
                final KeyStore ts = KeyStore.getInstance(ksType);
                ts.load(fis, tsPass.toCharArray());
                final TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
                tmf.init(ts);
                tm = tmf.getTrustManagers();
            } catch (KeyStoreException | IOException | CertificateException | NoSuchAlgorithmException ex) {
                throw new RuntimeException(ex);
            }
        }
        return tm;
    }
}

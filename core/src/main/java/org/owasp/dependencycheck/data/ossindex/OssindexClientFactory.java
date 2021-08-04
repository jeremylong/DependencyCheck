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
 * Copyright (c) 2019 Jason Dillon. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.ossindex;

import java.io.File;
import org.sonatype.goodies.packageurl.RenderFlavor;
import org.sonatype.ossindex.service.client.OssindexClient;
import org.sonatype.ossindex.service.client.OssindexClientConfiguration;
import org.sonatype.ossindex.service.client.marshal.Marshaller;
import org.sonatype.ossindex.service.client.marshal.GsonMarshaller;
import org.sonatype.ossindex.service.client.internal.OssindexClientImpl;
import org.sonatype.ossindex.service.client.transport.Transport;
import org.sonatype.ossindex.service.client.transport.UserAgentSupplier;
import org.owasp.dependencycheck.utils.Settings;

import java.io.IOException;
import org.joda.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonatype.ossindex.service.client.cache.DirectoryCache;
import org.sonatype.ossindex.service.client.transport.AuthConfiguration;

/**
 * Produces {@link OssindexClient} instances.
 *
 * @author Jason Dillon
 * @since 5.0.0
 */
public final class OssindexClientFactory {

    /**
     * Static logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(OssindexClientFactory.class);

    static {
        // prefer pkg scheme vs scheme-less variant
        RenderFlavor.setDefault(RenderFlavor.SCHEME);
    }

    /**
     * Private constructor for utility class.
     */
    private OssindexClientFactory() {
        //private constructor for utility class
    }

    /**
     * Constructs a new OSS Index Client.
     *
     * @param settings the configured settings
     * @return a new OSS Index Client
     */
    public static OssindexClient create(final Settings settings) {
        final OssindexClientConfiguration config = new OssindexClientConfiguration();

        final String baseUrl = settings.getString(Settings.KEYS.ANALYZER_OSSINDEX_URL, null);
        if (baseUrl != null) {
            config.setBaseUrl(baseUrl);
        }

        final String username = settings.getString(Settings.KEYS.ANALYZER_OSSINDEX_USER);
        final String password = settings.getString(Settings.KEYS.ANALYZER_OSSINDEX_PASSWORD);

        if (username != null && password != null) {
            final AuthConfiguration auth = new AuthConfiguration(username, password);
            config.setAuthConfiguration(auth);
        }

        final int batchSize = settings.getInt(Settings.KEYS.ANALYZER_OSSINDEX_BATCH_SIZE, OssindexClientConfiguration.DEFAULT_BATCH_SIZE);
        config.setBatchSize(batchSize);

        // proxy likely does not need to be configured here as we are using the
        // URLConnectionFactory#createHttpURLConnection() which automatically configures
        // the proxy on the connection.
//        ProxyConfiguration proxy = new ProxyConfiguration();
//        settings.getString(Settings.KEYS.PROXY_PASSWORD);
//        config.setProxyConfiguration(proxy);
        if (settings.getBoolean(Settings.KEYS.ANALYZER_OSSINDEX_USE_CACHE, true)) {
            final DirectoryCache.Configuration cache = new DirectoryCache.Configuration();
            final File data;
            try {
                data = settings.getDataDirectory();
                final File cacheDir = new File(data, "oss_cache");
                if (cacheDir.isDirectory() || cacheDir.mkdirs()) {
                    cache.setBaseDir(cacheDir.toPath());
                    cache.setExpireAfter(Duration.standardHours(24));
                    config.setCacheConfiguration(cache);
                    LOGGER.debug("OSS Index Cache: " + cache.toString());
                } else {
                    LOGGER.warn("Unable to use a cache for the OSS Index");
                }
            } catch (IOException ex) {
                LOGGER.warn("Unable to use a cache for the OSS Index", ex);
            }
        }
        // customize User-Agent for use with dependency-check
        final UserAgentSupplier userAgent = new UserAgentSupplier(
                "dependency-check",
                settings.getString(Settings.KEYS.APPLICATION_VERSION, "unknown")
        );

        final Transport transport = new ODCConnectionTransport(settings, config, userAgent);

        final Marshaller marshaller = new GsonMarshaller();

        return new OssindexClientImpl(config, transport, marshaller);
    }
}

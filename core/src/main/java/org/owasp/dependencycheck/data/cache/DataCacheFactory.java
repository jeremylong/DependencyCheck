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
 * Copyright (c) 2019 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.cache;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Properties;
import org.apache.commons.jcs.JCS;
import org.apache.commons.jcs.access.CacheAccess;
import org.apache.commons.jcs.access.exception.CacheException;
import org.apache.commons.jcs.engine.CompositeCacheAttributes;
import org.apache.commons.jcs.engine.behavior.ICompositeCacheAttributes;
import org.owasp.dependencycheck.data.nexus.MavenArtifact;
import org.owasp.dependencycheck.data.nodeaudit.Advisory;
import org.owasp.dependencycheck.utils.FileUtils;
import org.owasp.dependencycheck.utils.Settings;

/**
 * Factory to instantiate cache repositories.
 *
 * @author Jeremy Long
 */
public class DataCacheFactory {

    /**
     * The cache directory.
     */
    private String CACHE_DIRECTORY = "cache";
    /**
     * The cache properties.
     */
    private String CACHE_PROPERTIES = "dependencycheck-cache.properties";
    /**
     * A reference to the settings.
     */
    private Settings settings;
    /**
     * Whether or not JCS has been initialized.
     */
    private static boolean initialized = false;

    public enum CacheType {
        NODEAUDIT,
        CENTRAL
    }

    public DataCacheFactory(Settings settings) {
        if (!initialized) {
            this.settings = settings;

            File cacheDirectory;
            try {
                cacheDirectory = new File(settings.getDataDirectory(), CACHE_DIRECTORY);
            } catch (IOException ex) {
                throw new CacheException("Unable to obtain disk cache directory path");
            }
            if (!cacheDirectory.isDirectory() && !cacheDirectory.mkdirs()) {
                throw new CacheException("Unable to create disk cache: " + cacheDirectory.toString());
            }
            try (InputStream in = FileUtils.getResourceAsStream(CACHE_PROPERTIES)) {
                if (in == null) {
                    throw new RuntimeException("Cache properties `" + CACHE_PROPERTIES + "` could not be found");
                }

                Properties properties = new Properties();
                properties.load(in);
                properties.put("jcs.auxiliary.ODC.attributes.DiskPath", cacheDirectory.getCanonicalPath());
                for (CacheType t : CacheType.values()) {
                    File fp = new File(cacheDirectory, t.toString());
                    properties.put("jcs.auxiliary." + t.toString() + ".attributes.DiskPath", fp.getCanonicalPath());
                }

                JCS.setConfigProperties(properties);
                initialized = true;
            } catch (IOException ex) {
                throw new CacheException("Error creating disk cache", ex);
            }
        }
    }

    public DataCache getCache(CacheType type) {
        ICompositeCacheAttributes attr = new CompositeCacheAttributes();
        attr.setUseDisk(true);

        if (type == CacheType.NODEAUDIT) {
            CacheAccess<String, List<Advisory>> ca = JCS.getInstance(type.toString(), attr);
            DataCache<List<Advisory>> dc = new DataCache<>(ca);
            return dc;
        } else if (type == CacheType.CENTRAL) {
            CacheAccess<String, List<MavenArtifact>> ca = JCS.getInstance(type.toString(), attr);
            DataCache<List<MavenArtifact>> dc = new DataCache<>(ca);
            return dc;
        }
        return null;
    }

}

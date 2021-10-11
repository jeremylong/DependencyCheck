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
 * Copyright (c) 2021 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.update.nvd;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.time.Instant;
import org.apache.commons.io.FileUtils;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Simple four hour cache for files.
 *
 * @author Jeremy Long
 */
public class NvdCache {

    /**
     * The Logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(DownloadTask.class);
    /**
     * The settings.
     */
    private final Settings settings;

    /**
     * Creates a new cache for the NVD files.
     *
     * @param settings ODC settings
     */
    public NvdCache(Settings settings) {
        this.settings = settings;
    }

    /**
     * Checks if the file is in the cache and within four hours. If found and
     * viable, the cached data will be copied to the given file.
     *
     * @param url the URL of the file cached
     * @param file the path of the file to restore from the cache
     * @return <code>true</code> if the URL file is not in the cache; otherwise
     * <code>false</code>
     */
    public boolean notInCache(URL url, File file) {
        try {
            //valid for up to four hours.
            final long validEpoch = Instant.now().toEpochMilli() - 14400000;
            final File tmp = new File(url.getPath());
            final String filename = tmp.getName();
            final File cache = new File(settings.getDataDirectory(), "nvdcache");
            if (!cache.isDirectory()) {
                return true;
            }
            final File nvdFile = new File(cache, filename);
            if (nvdFile.isFile() && nvdFile.lastModified() > validEpoch) {
                LOGGER.debug("Copying {} from cache", url.toString());
                FileUtils.copyFile(nvdFile, file);
                return false;
            }
            return true;
        } catch (IOException ex) {
            LOGGER.debug("Error checking for nvd file in cache", ex);
            return true;
        }
    }

    /**
     * Stores a file in the cache.
     *
     * @param url the URL of the file to cache
     * @param file the file to cache
     */
    public void storeInCache(URL url, File file) {
        if (file.isFile()) {
            try {
                final File tmp = new File(url.getPath());
                final String filename = tmp.getName();
                final File cache = new File(settings.getDataDirectory(), "nvdcache");
                if (!cache.isDirectory() && !cache.mkdir()) {
                    return;
                }
                final File nvdFile = new File(cache, filename);
                FileUtils.copyFile(file, nvdFile);
                nvdFile.setLastModified(Instant.now().toEpochMilli());
            } catch (IOException ex) {
                LOGGER.debug("Error storing nvd file in cache", ex);
            }
        }
    }
}

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
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.update;

import java.net.MalformedURLException;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.owasp.dependencycheck.data.update.exception.UpdateException;
import org.owasp.dependencycheck.utils.DownloadFailedException;
import org.owasp.dependencycheck.utils.Settings;

/**
 * Class responsible for updating the NVD CVE and CPE data stores.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class NvdCveUpdater implements CachedWebDataSource {

    /**
     * The logger
     */
    private static final Logger LOGGER = Logger.getLogger(NvdCveUpdater.class.getName());

    /**
     * <p>
     * Downloads the latest NVD CVE XML file from the web and imports it into the current CVE Database.</p>
     *
     * @throws UpdateException is thrown if there is an error updating the database
     */
    @Override
    public void update() throws UpdateException {
        try {
            final StandardUpdate task = new StandardUpdate();
            if (task.isUpdateNeeded()) {
                task.update();
            }
        } catch (MalformedURLException ex) {
            LOGGER.log(Level.WARNING,
                    "NVD CVE properties files contain an invalid URL, unable to update the data to use the most current data.");
            LOGGER.log(Level.FINE, null, ex);
        } catch (DownloadFailedException ex) {
            LOGGER.log(Level.WARNING,
                    "Unable to download the NVD CVE data; the results may not include the most recent CPE/CVEs from the NVD.");
            if (Settings.getString(Settings.KEYS.PROXY_SERVER) == null) {
                LOGGER.log(Level.INFO,
                        "If you are behind a proxy you may need to configure dependency-check to use the proxy.");
            }
            LOGGER.log(Level.FINE, null, ex);
        }
    }
}

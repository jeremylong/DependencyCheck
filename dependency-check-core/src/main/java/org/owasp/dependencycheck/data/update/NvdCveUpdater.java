/*
 * This file is part of dependency-check-core.
 *
 * Dependency-check-core is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-check-core is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * dependency-check-core. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.update;

import org.owasp.dependencycheck.data.update.exception.UpdateException;
import java.net.MalformedURLException;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.owasp.dependencycheck.utils.DownloadFailedException;

/**
 * Class responsible for updating the NVD CVE and CPE data stores.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class NvdCveUpdater implements CachedWebDataSource {

    /**
     * <p>Downloads the latest NVD CVE XML file from the web and imports it into
     * the current CVE Database.</p>
     *
     * @throws UpdateException is thrown if there is an error updating the
     * database
     */
    @Override
    public void update() throws UpdateException {
        try {
            final StandardUpdate task = new StandardUpdate();
            if (task.isUpdateNeeded()) {
                task.update();
            }
        } catch (MalformedURLException ex) {
            Logger.getLogger(NvdCveUpdater.class.getName()).log(Level.WARNING,
                    "NVD CVE properties files contain an invalid URL, unable to update the data to use the most current data.");
            Logger.getLogger(NvdCveUpdater.class.getName()).log(Level.FINE, null, ex);
        } catch (DownloadFailedException ex) {
            Logger.getLogger(NvdCveUpdater.class.getName()).log(Level.WARNING,
                    "Unable to download the NVD CVE data, unable to update the data to use the most current data.");
            Logger.getLogger(NvdCveUpdater.class.getName()).log(Level.FINE, null, ex);
        }
    }
}

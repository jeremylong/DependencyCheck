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
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.cpe;

import java.io.File;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.lucene.store.Directory;
import org.apache.lucene.store.FSDirectory;
import org.owasp.dependencycheck.utils.Settings;

/**
 * The Base Index class used to access the CPE Index.
 *
 * @author Jeremy Long (jeremy.long@owasp.org)
 */
public abstract class BaseIndex {

    /**
     * The Lucene directory containing the index.
     */
    protected Directory directory;
    /**
     * Indicates whether or not the Lucene Index is open.
     */
    protected boolean indexOpen = false;

    /**
     * Opens the CPE Index.
     *
     * @throws IOException is thrown if an IOException occurs opening the index.
     */
    public void open() throws IOException {
        directory = this.openDirectory();
        indexOpen = true;
    }

    /**
     * Closes the CPE Index.
     */
    public void close() {
        try {
            directory.close();
        } catch (IOException ex) {
            final String msg = "Unable to update database due to an IO error.";
            Logger.getLogger(BaseIndex.class.getName()).log(Level.SEVERE, msg);
            Logger.getLogger(BaseIndex.class.getName()).log(Level.FINE, null, ex);
        } finally {
            directory = null;
        }
        indexOpen = false;

    }

    /**
     * Returns the status of the data source - is the index open.
     *
     * @return true or false.
     */
    public boolean isOpen() {
        return indexOpen;
    }

    /**
     * Returns the Lucene directory object for the CPE Index.
     *
     * @return the Lucene Directory object for the CPE Index.
     * @throws IOException is thrown if an IOException occurs.
     */
    protected Directory openDirectory() throws IOException {
        final File path = getDataDirectory();
        return FSDirectory.open(path);
    }

    /**
     * Retrieves the directory that the JAR file exists in so that we can ensure
     * we always use a common data directory.
     *
     * @return the data directory for this index.
     * @throws IOException is thrown if an IOException occurs of course...
     */
    public static File getDataDirectory() throws IOException {
        final File path = Settings.getFile(Settings.KEYS.CPE_DATA_DIRECTORY);
        if (!path.exists()) {
            if (!path.mkdirs()) {
                throw new IOException("Unable to create CPE Data directory");
            }
        }
        return path;
    }
}

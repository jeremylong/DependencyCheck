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

import java.net.MalformedURLException;
import org.owasp.dependencycheck.data.UpdateException;
import org.owasp.dependencycheck.utils.DownloadFailedException;

/**
 * An UpdateTask Factory that instantiates the correct UpdateTask based on the
 * given configuration.
 *
 * @author Jeremy Long (jeremy.long@owasp.org)
 */
public final class UpdateTaskFactory {

    /**
     * private constructor for a utility class.
     */
    private UpdateTaskFactory() {
        //empty contrusctor for utility class
    }

    /**
     * Constructs the appropriate update task based on configuration.
     *
     * @return an UpdateTask
     * @throws MalformedURLException thrown if a configured URL is malformed
     * @throws DownloadFailedException thrown if a timestamp cannot be checked
     * on a configured URL
     * @throws UpdateException thrown if there is an exception generating the
     * update task
     */
    public static UpdateTask getUpdateTask() throws MalformedURLException, DownloadFailedException, UpdateException {
        final UpdateTask task;
        final DataStoreMetaInfo properties = new DataStoreMetaInfo();
        if (properties.isBatchUpdateMode()) {
            task = new BatchUpdateTask(properties);
        } else {
            task = new StandardUpdateTask(properties);
        }
        return task;
    }
}

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

/**
 * Defines a data source who's data is retrieved from the Internet. This data
 * can be downloaded and the local cache updated.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public interface CachedWebDataSource {

    /**
     * Determines if an update to the current data store is needed, if it is the
     * new data is downloaded from the Internet and imported into the current
     * cached data store.
     *
     * @throws UpdateException is thrown if there is an exception downloading
     * the data or updating the data store.
     */
    void update() throws UpdateException;
}

/*
 * This file is part of Dependency-Check.
 *
 * Dependency-Check is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-Check is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Dependency-Check. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data;

/**
 * Defines an Index who's data is retrieved from the Internet. This data can be
 * downloaded and the index updated.
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public interface CachedWebDataSource {

    /**
     * Determines if an update to the current index is needed, if it is the new
     * data is downloaded from the Internet and imported into the current Lucene
     * Index.
     *
     * @throws UpdateException is thrown if there is an exception updating the
     * index.
     */
    void update() throws UpdateException;
}

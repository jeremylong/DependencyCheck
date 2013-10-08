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

import org.owasp.dependencycheck.data.UpdateException;

/**
 * An interface defining an update task.
 *
 * @author Jeremy Long (jeremy.long@owasp.org)
 */
public interface UpdateTask {

    /**
     * <p>Updates the data store to the latest version.</p>
     *
     * @throws UpdateException is thrown if there is an error updating the
     * database
     */
    void update() throws UpdateException;

    /**
     * Get the value of deleteAndRecreate.
     *
     * @return the value of deleteAndRecreate
     */
    boolean shouldDeleteAndRecreate();

    /**
     * Gets whether or not an update is needed.
     *
     * @return true or false depending on whether an update is needed
     */
    boolean isUpdateNeeded();
}

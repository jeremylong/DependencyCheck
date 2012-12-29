package org.codesecure.dependencycheck.data.nvdcve.xml;
/*
 * This file is part of DependencyCheck.
 *
 * DependencyCheck is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * DependencyCheck is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * DependencyCheck. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */

/**
 * An InvalidataDataException is a generic exception used when trying to load
 * the nvd cve meta data.
 *
 * @author Jeremy
 */
public class InvalidDataException extends Exception {

    /**
     * Creates an InvalidDataException
     *
     * @param msg the exception message
     */
    public InvalidDataException(String msg) {
        super(msg);
    }

    /**
     * Creates an InvalidDataException
     *
     * @param msg the exception message
     * @param ex the cause of the exception
     */
    public InvalidDataException(String msg, Exception ex) {
        super(msg, ex);
    }
}

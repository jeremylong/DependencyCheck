package org.codesecure.dependencycheck.data.cpe;
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
 * Fields is a collection of field names used within the Lucene index for CPE
 * entries.
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public abstract class Fields {

    /**
     * The key for the name field.
     */
    public static final String NAME = "name";
    /**
     * The key for the vendor field.
     */
    public static final String VENDOR = "vendor";
    /**
     * The key for the product field.
     */
    public static final String PRODUCT = "product";
    /**
     * The key for the version field.
     */
    public static final String VERSION = "version";
    //public static final String REVISION = "revision";
}

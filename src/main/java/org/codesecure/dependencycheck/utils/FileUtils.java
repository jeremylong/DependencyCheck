package org.codesecure.dependencycheck.utils;
/*
 * This file is part of DependencyCheck.
 *
 * DependencyCheck is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * DependencyCheck is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with DependencyCheck. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */

/**
 * A collection of utilities for processing information about files.
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public class FileUtils {

    /**
     * Returns the (lowercase) file extension for a specified file.
     * @param fileName the file name to retrieve the file extension from.
     * @return the file extension.
     */
    public static String getFileExtension(String fileName) {
        String ret = null;
        int pos = fileName.lastIndexOf(".");
        if (pos >= 0) {
            ret = fileName.substring(pos + 1, fileName.length()).toLowerCase();
        }
        return ret;
    }
}

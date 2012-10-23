package org.codesecure.dependencycheck.data.cpe.xml;
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

import org.codesecure.dependencycheck.data.cpe.Entry;
import java.io.IOException;
import org.apache.lucene.index.CorruptIndexException;

/**
 *
 * An interface used to define the save function used when parsing the CPE XML
 * file.
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public interface EntrySaveDelegate {

    /**
     * Saves a CPE Entry into the Lucene index.
     *
     * @param entry a CPE entry.
     * @throws CorruptIndexException is thrown if the index is corrupt.
     * @throws IOException is thrown if an IOException occurs.
     */
    void saveEntry(Entry entry) throws CorruptIndexException, IOException;
}

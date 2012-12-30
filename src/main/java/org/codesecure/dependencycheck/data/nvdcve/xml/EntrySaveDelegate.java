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
package org.codesecure.dependencycheck.data.nvdcve.xml;

import java.io.IOException;
import org.apache.lucene.index.CorruptIndexException;
import org.codesecure.dependencycheck.data.nvdcve.generated.VulnerabilityType;

/**
 *
 * An interface used to define the save function used when parsing the NVD CVE
 * XML file.
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public interface EntrySaveDelegate {

    /**
     * Saves a CVE Entry into the Lucene index.
     *
     * @param vulnerability a CVE entry.
     * @throws CorruptIndexException is thrown if the index is corrupt.
     * @throws IOException is thrown if an IOException occurs.
     */
    void saveEntry(VulnerabilityType vulnerability) throws CorruptIndexException, IOException;
}

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
package org.owasp.dependencycheck.data.cwe;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public final class CweDB {

    /**
     * Empty private constructor as this is a utility class.
     */
    private CweDB() {
        //empty
    }
    /**
     * A HashMap of the CWE data.
     */
    private static final HashMap<String, String> CWE = loadData();

    /**
     * Loads a HashMap containing the CWE data from a resource found in the jar.
     *
     * @return a HashMap of CWE data
     */
    private static HashMap<String, String> loadData() {
        ObjectInputStream oin = null;
        try {
            final String filePath = "data/cwe.hashmap.serialized";
            final InputStream input = CweDB.class.getClassLoader().getResourceAsStream(filePath);
            oin = new ObjectInputStream(input);
            return (HashMap<String, String>) oin.readObject();
        } catch (ClassNotFoundException ex) {
            Logger.getLogger(CweDB.class.getName()).log(Level.WARNING, "Unable to load CWE data. This should not be an issue.");
            Logger.getLogger(CweDB.class.getName()).log(Level.FINE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(CweDB.class.getName()).log(Level.WARNING, "Unable to load CWE data due to an IO Error. This should not be an issue.");
            Logger.getLogger(CweDB.class.getName()).log(Level.FINE, null, ex);
        } finally {
            if (oin != null) {
                try {
                    oin.close();
                } catch (IOException ex) {
                    Logger.getLogger(CweDB.class.getName()).log(Level.FINEST, null, ex);
                }
            }
        }
        return null;
    }

    /**
     * <p>Returns the full CWE name from the CWE ID.</p>
     *
     * @param cweId the CWE ID
     * @return the full name of the CWE
     */
    public static String getCweName(String cweId) {
        if (cweId != null) {
            return CWE.get(cweId);
        }
        return null;
    }
}

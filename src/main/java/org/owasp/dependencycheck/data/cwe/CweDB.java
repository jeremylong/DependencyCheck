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
package org.owasp.dependencycheck.data.cwe;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public class CweDB {

    private CweDB() {
        //empty constructor for utility class
    }
    private static final HashMap<String, String> CWE = loadData();

    private static HashMap<String, String> loadData() {
        ObjectInputStream oin = null;
        try {
            String filePath = "data/cwe.hashmap.serialized";
            InputStream input = CweDB.class.getClassLoader().getResourceAsStream(filePath);
            oin = new ObjectInputStream(input);
            @SuppressWarnings("unchecked")
            HashMap<String, String> data = (HashMap<String, String>) oin.readObject();
            return data;
        } catch (ClassNotFoundException ex) {
            Logger.getLogger(CweDB.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(CweDB.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            if (oin != null) {
                try {
                    oin.close();
                } catch (IOException ex) {
                    Logger.getLogger(CweDB.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        }
        return null;
    }

    /**
     * <p>Returns the full CWE name from the CWE ID.</p>
     * @param cweId te CWE ID
     * @return the full name of the CWE
     */
    public static String getCweName(String cweId) {
        if (cweId != null) {
            return CWE.get(cweId);
        }
        return null;
    }
}

/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.codesecure.dependencycheck.data.cwe;

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
        //empty contructor for utility class
    }

    private static final HashMap<String, String> cwe = loadData();

    private static HashMap<String, String> loadData() {
        ObjectInputStream oin = null;
        try {
            String filePath = "data/cwe.hashmap.serialized";
            InputStream input = CweDB.class.getClassLoader().getResourceAsStream(filePath);
            oin = new ObjectInputStream(input);
            @SuppressWarnings("unchecked")
            HashMap<String,String> data = (HashMap<String,String>) oin.readObject();
            return data;
        } catch (ClassNotFoundException ex) {
            Logger.getLogger(CweDB.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(CweDB.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                oin.close();
            } catch (IOException ex) {
                Logger.getLogger(CweDB.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        return null;
    }

    public static String getCweName(String cweId) {
        if (cweId != null) {
            return cwe.get(cweId);
        }
        return null;
    }

}

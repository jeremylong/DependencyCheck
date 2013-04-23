/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.owasp.dependencycheck.utils;

import java.util.regex.MatchResult;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public final class DependencyVersionUtil {
    //private final static Pattern RX_VERSION = Pattern.compile("\\d+(\\.\\d+)*(\\d+[a-zA-Z]{1,3}\\d+)?");
    private final static Pattern RX_VERSION = Pattern.compile("\\d+(\\.\\d+)+(\\.?[a-zA-Z_-]{1,3}\\d+)?");

    /**
     * Private constructor for utility class.
     */
    private DependencyVersionUtil() {
    }

    public static DependencyVersion parseVersionFromFileName(String filename) {
        if (filename == null) {
            return null;
        }
        String version = null;
        Matcher matcher = RX_VERSION.matcher(filename);
        if (matcher.find()) {
            version = matcher.group();
        }
        //throw away the results if there are two things that look like version numbers
        if (matcher.find()) {
            return null;
        }
        if (version == null) {
            return null;
        }
        return new DependencyVersion(version);


//        String name = null;
//        final int pos = filename.lastIndexOf('.');
//        if (pos>0) {
//            name = filename.substring(0, pos).toLowerCase();
//        } else {
//            name = filename.toLowerCase();
//        }
////        if (name.endsWith("-snapshot")) {
////            name = name.substring(0,name.length() - 9);
////        }
////        if (name.endsWith("-release")) {
////            name = name.substring(0,name.length() - 8);
////        }
//        final String[] parts = name.split("[_-]");
//        if (parts == null || parts.length == 0) {
//            return null;
//        }
//        for (int x = parts.length - 1; x >= 0; x--) {
//            if (RX_VERSION.matcher(parts[x]).matches()) {
//                return new DependencyVersion(parts[x]);
//            }
//        }
//        return null;
    }
}

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

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * A utility to download files from the Internet.
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public class Downloader {

    /**
     * Private constructor for utility class.
     */
    private Downloader() {

    }

    /**
     * Retrieves a file from a given URL and saves it to the outputPath.
     * @param url the URL of the file to download.
     * @param outputPath the path to the save the file to.
     * @throws IOException is thrown if an IOException occurs.
     */
    public static void fetchFile(URL url, String outputPath) throws IOException {
        File f = new File(outputPath);
        fetchFile(url, f);
    }

    /**
     * Retrieves a file from a given URL and saves it to the outputPath.
     * @param url the URL of the file to download.
     * @param outputPath the path to the save the file to.
     * @throws IOException is thrown if an IOException occurs.
     */
    public static void fetchFile(URL url, File outputPath) throws IOException {
        url.openConnection();
        BufferedOutputStream writer = null;
        try {
            InputStream reader = url.openStream();
            writer = new BufferedOutputStream(new FileOutputStream(outputPath));
            byte[] buffer = new byte[4096];
            int bytesRead = 0;
            while ((bytesRead = reader.read(buffer)) > 0) {
                writer.write(buffer, 0, bytesRead);
            }
        } catch (Exception ex) {
            Logger.getLogger(Downloader.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                writer.close();
                writer = null;
            } catch (Exception ex) {
                Logger.getLogger(Downloader.class.getName()).log(Level.WARNING,
                        "Error closing the writter in Downloader.", ex);
            }
        }
    }
}

/*
 * This file is part of dependency-check-core.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) 2019 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.nvd.json;

import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Properties;
import org.owasp.dependencycheck.data.update.exception.InvalidDataException;

/**
 * Meta properties object to hold information about the NVD CVE data.
 *
 * @author Jeremy Long
 */
public class MetaProperties {

    /**
     * The SHA256 of the NVD file.
     */
    private String sha256;
    /**
     * The last modified date of the NVD file in epoch time.
     */
    private long lastModifiedDate;
    /**
     * The size of the NVD file.
     */
    private long size;
    /**
     * The size of the zipped NVD file.
     */
    private long zipSize;
    /**
     * The size of the gzipped NVD file.
     */
    private long gzSize;

    /**
     * Get the value of gzSize.
     *
     * @return the value of gzSize
     */
    public long getGzSize() {
        return gzSize;
    }

    /**
     * Get the value of zipSize.
     *
     * @return the value of zipSize
     */
    public long getZipSize() {
        return zipSize;
    }

    /**
     * Get the value of size.
     *
     * @return the value of size
     */
    public long getSize() {
        return size;
    }

    /**
     * Get the value of lastModifiedDate in epoch time.
     *
     * @return the value of lastModifiedDate
     */
    public long getLastModifiedDate() {
        return lastModifiedDate;
    }

    /**
     * Get the value of SHA256.
     *
     * @return the value of SHA256
     */
    public String getSha256() {
        return sha256;
    }

    /**
     * Constructs a new MetaProperties object to hold information about the NVD
     * data.
     *
     * @param contents the contents of the meta file
     * @throws InvalidDataException thrown if the meta file contents cannot be
     * parsed
     */
    public MetaProperties(String contents) throws InvalidDataException {
        final Properties properties = new Properties();
        try (Reader r = new StringReader(contents)) {
            properties.load(r);
        } catch (IOException ex) {
            throw new InvalidDataException("Unable to parse meta file data", ex);
        }
        this.sha256 = properties.getProperty("sha256");
        try {
            final String date = properties.getProperty("lastModifiedDate");
            if (date == null) {
                throw new InvalidDataException("lastModifiedDate not found in meta file");
            }
            this.lastModifiedDate = ZonedDateTime.parse(date, DateTimeFormatter.ISO_OFFSET_DATE_TIME).toEpochSecond();
        } catch (DateTimeParseException ex) {
            throw new InvalidDataException("Meta file lastModifiedDate cannot be parsed: "
                    + properties.getProperty("lastModifiedDate"), ex);
        }
        try {
            this.zipSize = Long.parseLong(properties.getProperty("zipSize"));
        } catch (NumberFormatException ex) {
            throw new InvalidDataException("Meta file zip size cannot be parsed: "
                    + properties.getProperty("zipSize"), ex);
        }
        try {
            this.gzSize = Long.parseLong(properties.getProperty("gzSize"));
        } catch (NumberFormatException ex) {
            throw new InvalidDataException("Meta file gz size cannot be parsed: "
                    + properties.getProperty("gzSize"), ex);
        }
        try {
            this.size = Long.parseLong(properties.getProperty("size"));
        } catch (NumberFormatException ex) {
            throw new InvalidDataException("Meta file size cannot be parsed: "
                    + properties.getProperty("size"), ex);
        }
    }
}

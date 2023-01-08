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
 * Copyright (c) 2018 Steve Springett. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.update.nvd;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.module.blackbird.BlackbirdModule;
import com.fasterxml.jackson.module.afterburner.AfterburnerModule;

import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import static java.nio.charset.StandardCharsets.UTF_8;
import java.util.zip.GZIPInputStream;
import java.util.zip.ZipException;

import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.data.update.exception.CorruptedDatastreamException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.owasp.dependencycheck.data.nvd.json.DefCveItem;
import org.owasp.dependencycheck.data.nvd.ecosystem.CveEcosystemMapper;
import org.owasp.dependencycheck.data.update.exception.UpdateException;
import org.owasp.dependencycheck.utils.Settings;

/**
 * Parser and processor of NVD CVE JSON data feeds.
 *
 * @author Jeremy Long
 */
public final class NvdCveParser {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(NvdCveParser.class);
    /**
     * A reference to the CVE DB.
     */
    private final CveDB cveDB;
    /**
     * A reference to the ODC settings.
     */
    private final Settings settings;

    /**
     * Creates a new NVD CVE JSON Parser.
     *
     * @param settings the dependency-check settings
     * @param db a reference to the database
     */
    public NvdCveParser(Settings settings, CveDB db) {
        this.settings = settings;
        this.cveDB = db;
    }

    /**
     * Parses the NVD JSON file and inserts/updates data into the database.
     *
     * @param file the NVD JSON file to parse
     * @throws UpdateException thrown if the file could not be read
     * @throws CorruptedDatastreamException thrown if the file was found to be a
     * corrupted download (ZipException or premature EOF)
     */
    public void parse(File file) throws UpdateException, CorruptedDatastreamException {
        LOGGER.debug("Parsing " + file.getName());

        final Module module;
        if (getJavaVersion() <= 8) {
            module = new AfterburnerModule();
        } else {
            module = new BlackbirdModule();
        }
        final ObjectMapper objectMapper = JsonMapper.builder()
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
                .addModule(module)
                .build();

        final ObjectReader objectReader = objectMapper.readerFor(DefCveItem.class);

        try (InputStream fin = new FileInputStream(file);
                InputStream in = new GZIPInputStream(fin);
                InputStreamReader isr = new InputStreamReader(in, UTF_8);
                JsonParser parser = objectReader.getFactory().createParser(isr)) {

            final CveEcosystemMapper mapper = new CveEcosystemMapper();
            init(parser);
            while (parser.nextToken() == JsonToken.START_OBJECT) {
                final DefCveItem cve = objectReader.readValue(parser);
                cveDB.updateVulnerability(cve, mapper.getEcosystem(cve));
            }
        } catch (FileNotFoundException ex) {
            LOGGER.error(ex.getMessage());
            throw new UpdateException("Unable to find the NVD CVE file, `" + file + "`, to parse", ex);
        } catch (ZipException | EOFException ex) {
            throw new CorruptedDatastreamException("Error parsing NVD CVE file", ex);
        } catch (IOException ex) {
            LOGGER.error("Error reading NVD JSON data: {}", file);
            LOGGER.debug("Error extracting the NVD JSON data from: " + file, ex);
            throw new UpdateException("Unable to find the NVD CVE file to parse", ex);
        }
    }

    /**
     * Returns the Java major version as a whole number.
     *
     * @return the Java major version as a whole number
     */
    private static int getJavaVersion() {
        String version = System.getProperty("java.specification.version");
        if (version.startsWith("1.")) {
            version = version.substring(2, 3);
        } else {
            final int dot = version.indexOf(".");
            if (dot != -1) {
                version = version.substring(0, dot);
            }
        }
        return Integer.parseInt(version);
    }

    void init(JsonParser parser) throws IOException {
        JsonToken nextToken = parser.nextToken();
        if (nextToken != JsonToken.START_OBJECT) {
            throw new IOException("Expected " + JsonToken.START_OBJECT + ", got " + nextToken);
        }

        do {
            nextToken = parser.nextToken();
            if (nextToken == null) {
                break;
            }

            if (nextToken.isStructStart()) {
                if (nextToken == JsonToken.START_ARRAY) {
                    break;
                } else {
                    parser.skipChildren();
                }
            }
        } while (true);
    }
}

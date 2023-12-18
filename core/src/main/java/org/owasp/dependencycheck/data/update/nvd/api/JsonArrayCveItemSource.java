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
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.update.nvd.api;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.github.jeremylong.openvulnerability.client.nvd.DefCveItem;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.zip.GZIPInputStream;

public class JsonArrayCveItemSource implements CveItemSource<DefCveItem> {

    private final File jsonFile;
    private final ObjectMapper mapper;
    private final InputStream inputStream;
    private final JsonParser jsonParser;
    private DefCveItem currentItem;
    private DefCveItem nextItem;

    public JsonArrayCveItemSource(File jsonFile) throws IOException {
        this.jsonFile = jsonFile;
        mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());
        inputStream = jsonFile.getName().endsWith(".gz") ?
                new BufferedInputStream(new GZIPInputStream(Files.newInputStream(jsonFile.toPath()))) :
                new BufferedInputStream(Files.newInputStream(jsonFile.toPath()));
        jsonParser = mapper.getFactory().createParser(inputStream);

        if (jsonParser.nextToken() == JsonToken.START_ARRAY) {
            nextItem = readItem(jsonParser);
        }
    }

    @Override
    public void close() throws Exception {
        jsonParser.close();
        inputStream.close();
        Files.delete(jsonFile.toPath());
    }

    @Override
    public boolean hasNext() {
        return nextItem != null;
    }

    @Override
    public DefCveItem next() throws IOException {
        currentItem = nextItem;
        nextItem = readItem(jsonParser);
        return currentItem;
    }

    private DefCveItem readItem(JsonParser jsonParser) throws IOException {
        if (jsonParser.nextToken() == JsonToken.START_OBJECT) {
            return mapper.readValue(jsonParser, DefCveItem.class);
        }
        return null;
    }
}

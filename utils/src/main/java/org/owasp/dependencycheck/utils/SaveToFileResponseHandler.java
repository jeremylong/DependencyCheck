/*
 * This file is part of dependency-check-utils.
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
 * Copyright (c) 2024 Hans Aikema. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

import org.apache.hc.client5.http.impl.classic.AbstractHttpClientResponseHandler;
import org.apache.hc.core5.http.HttpEntity;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.channels.ReadableByteChannel;

class SaveToFileResponseHandler extends AbstractHttpClientResponseHandler<Void> {

    /**
     * The output path where the response content should be stored as a file
     */
    private final File outputPath;

    SaveToFileResponseHandler(File outputPath) {
        this.outputPath = outputPath;
    }

    @Override
    public Void handleEntity(HttpEntity responseEntity) throws IOException {
        try (InputStream in = responseEntity.getContent();
             ReadableByteChannel sourceChannel = Channels.newChannel(in);
             FileOutputStream fos = new FileOutputStream(outputPath);
             FileChannel destChannel = fos.getChannel()) {
            final ByteBuffer buffer = ByteBuffer.allocateDirect(8192);
            while (sourceChannel.read(buffer) != -1) {
                buffer.flip();
                destChannel.write(buffer);
                buffer.compact();
            }
        }
        return null;
    }

}

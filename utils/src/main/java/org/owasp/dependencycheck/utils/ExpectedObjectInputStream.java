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
 * Copyright (c) 2016 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

import java.io.IOException;
import java.io.InputStream;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * An ObjectInputStream that will only deserialize expected classes.
 *
 * @author Jeremy Long
 * @version $Id: $Id
 */
// NotThreadSafe
public class ExpectedObjectInputStream extends ObjectInputStream {

    /**
     * The list of fully qualified class names that are able to be deserialized.
     */
    private final List<String> expected = new ArrayList<>();

    /**
     * Constructs a new ExpectedOjectInputStream that can be used to securely deserialize an object by restricting the classes
     * that can deserialized to a known set of expected classes.
     *
     * @param inputStream the input stream that contains the object to deserialize
     * @param expected the fully qualified class names of the classes that can be deserialized
     * @throws java.io.IOException thrown if there is an error reading from the stream
     */
    public ExpectedObjectInputStream(InputStream inputStream, String... expected) throws IOException {
        super(inputStream);
        this.expected.addAll(Arrays.asList(expected));
    }

    /**
     * {@inheritDoc}
     *
     * Only deserialize instances of expected classes by validating the class name prior to deserialization.
     */
    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
        if (!this.expected.contains(desc.getName())) {
            throw new InvalidClassException("Unexpected deserialization ", desc.getName());
        }
        return super.resolveClass(desc);
    }
}

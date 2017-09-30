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
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.cpe;

import javax.annotation.concurrent.ThreadSafe;

/**
 * Fields is a collection of field names used within the Lucene index for CPE
 * entries.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public final class Fields {

    /**
     * The key for the name document id.
     */
    public static final String DOCUMENT_KEY = "id";
    /**
     * The key for the vendor field.
     */
    public static final String VENDOR = "vendor";
    /**
     * The key for the product field.
     */
    public static final String PRODUCT = "product";

    /**
     * Private constructor as this is more of an enumeration rather then a full
     * class.
     */
    private Fields() {
    }
}

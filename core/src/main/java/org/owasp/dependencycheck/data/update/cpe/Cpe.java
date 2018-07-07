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
 * Copyright (c) 2015 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.update.cpe;

import org.apache.commons.lang3.StringUtils;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import javax.annotation.concurrent.ThreadSafe;
import org.owasp.dependencycheck.data.update.exception.InvalidDataException;

/**
 *
 * @author Jeremy Long
 */
@ThreadSafe
public class Cpe {

    /**
     * The CPE identifier string (cpe:/a:vendor:product:version).
     */
    private String value;
    /**
     * The vendor portion of the identifier.
     */
    private String vendor;

    /**
     * The product portion of the identifier.
     */
    private String product;

    /**
     * Constructs a new Cpe Object by parsing the vendor and product from the CPE identifier value.
     *
     * @param value the cpe identifier (cpe:/a:vendor:product:version:....)
     * @throws UnsupportedEncodingException thrown if UTF-8 is not supported
     * @throws InvalidDataException thrown if the CPE provided is not the correct format
     */
    public Cpe(String value) throws UnsupportedEncodingException, InvalidDataException {
        this.value = value;
        final String valueWithoutPrefix = value.substring(7);
        final String[] data = StringUtils.split(valueWithoutPrefix, ':');
        if (data.length >= 2) {
            vendor = URLDecoder.decode(data[0].replace("+", "%2B"), StandardCharsets.UTF_8.name());
            product = URLDecoder.decode(data[1].replace("+", "%2B"), StandardCharsets.UTF_8.name());
        } else {
            throw new InvalidDataException(String.format("CPE has an invalid format: %s", value));
        }
    }

    /**
     * Get the value of value.
     *
     * @return the value of value
     */
    public String getValue() {
        return value;
    }

    /**
     * Set the value of value.
     *
     * @param value new value of value
     */
    public void setValue(String value) {
        this.value = value;
    }

    /**
     * Get the value of vendor.
     *
     * @return the value of vendor
     */
    public String getVendor() {
        return vendor;
    }

    /**
     * Set the value of vendor.
     *
     * @param vendor new value of vendor
     */
    public void setVendor(String vendor) {
        this.vendor = vendor;
    }

    /**
     * Get the value of product.
     *
     * @return the value of product
     */
    public String getProduct() {
        return product;
    }

    /**
     * Set the value of product.
     *
     * @param product new value of product
     */
    public void setProduct(String product) {
        this.product = product;
    }

    /**
     * Returns the full CPE identifier.
     *
     * @return the full CPE identifier
     */
    @Override
    public String toString() {
        return value;
    }
}

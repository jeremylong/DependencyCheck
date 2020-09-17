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
 * Copyright (c) 2020 The OWASP Foundation. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.nvd.ecosystem;

public enum EcosystemHintNature {
    /**
     * Hint is from the file extension.
     */
    FILE_EXTENSION,
    /**
     * Hint is from a keyword.
     */
    KEYWORD,
    /**
     * Hint is from the host in a URL.
     */
    URL_HOST,
    /**
     * Hint is from the URL path.
     */
    URL_PATH;
}

/*
 * This file is part of dependency-check-ant.
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
 * Copyright (c) 2015 The OWASP Foundation. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

import ch.qos.cal10n.BaseName;
import ch.qos.cal10n.Locale;
import ch.qos.cal10n.LocaleData;

/**
 * @author colezlaw
 */
@BaseName("dependencycheck-resources")
@LocaleData(defaultCharset = "UTF-8",
        value = {
            @Locale("en")
        }
)
public enum DCResources {

    /**
     * Not deployed.
     */
    NOTDEPLOYED,
    /**
     * grok error.
     */
    GROKERROR,
    /**
     * The dependency is not an assembly.
     */
    NOTASSEMBLY,
    /**
     * GROK Return Code.
     */
    GROKRC,
    /**
     * Grok assembly was extracted.
     */
    GROKDEPLOYED,
    /**
     * Grok assembly was not extracted.
     */
    GROKNOTDEPLOYED,
    /**
     * Grok failed to initialize.
     */
    GROKINITFAIL,
    /**
     * Grok initialized.
     */
    GROKINITMSG,
    /**
     * Grok assembly was not deleted.
     */
    GROKNOTDELETED
}

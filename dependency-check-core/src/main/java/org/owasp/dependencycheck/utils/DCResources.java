package org.owasp.dependencycheck.utils;

import ch.qos.cal10n.BaseName;
import ch.qos.cal10n.Locale;
import ch.qos.cal10n.LocaleData;

/**
 * Created by colezlaw on 6/13/15.
 */
@BaseName("dependencycheck-resources")
@LocaleData(defaultCharset = "UTF-8",
    value = {
        @Locale("en")
    }
)
public enum DCResources {
    NOTDEPLOYED,
    GROKERROR,
    NOTASSEMBLY,
    GROKRC,
    GROKDEPLOYED,
    GROKNOTDEPLOYED,
    GROKINITFAIL,
    GROKINITMSG,
    GROKNOTDELETED
}

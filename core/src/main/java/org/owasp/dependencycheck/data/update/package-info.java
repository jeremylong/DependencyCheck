/**
 *
 * Contains classes used to update the data stores.<br><br>
 *
 * The UpdateService will load, any correctly defined CachedWebDataSource(s) and call update() on them. The Cached Data Source
 * must determine if it needs to be updated and if so perform the update. The sub packages contain classes used to perform the
 * actual updates.
 */
package org.owasp.dependencycheck.data.update;

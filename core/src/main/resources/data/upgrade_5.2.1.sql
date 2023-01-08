--TODO move to upgrade_5.3
--CREATE TABLE knownExploited (cveID varchar(20) PRIMARY KEY,
--    vendorProject VARCHAR(255),
--    product VARCHAR(255),
--    vulnerabilityName VARCHAR(500),
--    dateAdded CHAR(10),
--    shortDescription VARCHAR(2000),
--    requiredAction VARCHAR(1000),
--    dueDate CHAR(10),
--    notes VARCHAR(2000));
--
--CREATE ALIAS merge_knownexploited FOR "org.owasp.dependencycheck.data.nvdcve.H2Functions.mergeKnownExploited";
--
--UPDATE Properties SET `value`='5.4' WHERE ID='version';

ALTER TABLE software ALTER COLUMN versionEndExcluding SET DATA TYPE VARCHAR(100);
ALTER TABLE software ALTER COLUMN versionEndIncluding SET DATA TYPE VARCHAR(100);
ALTER TABLE software ALTER COLUMN versionStartExcluding SET DATA TYPE VARCHAR(100);
ALTER TABLE software ALTER COLUMN versionStartIncluding SET DATA TYPE VARCHAR(100);

UPDATE Properties SET `value`='5.3' WHERE ID='version'; 


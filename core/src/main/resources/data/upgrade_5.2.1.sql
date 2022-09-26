
CREATE TABLE knownExploited (cveID varchar(20) PRIMARY KEY,
    vendorProject VARCHAR(255),
    product VARCHAR(255),
    vulnerabilityName VARCHAR(500),
    dateAdded CHAR(10),
    shortDescription VARCHAR(2000),
    requiredAction VARCHAR(1000),
    dueDate CHAR(10),
    notes VARCHAR(2000));

CREATE ALIAS update_knownexpoited FOR "org.owasp.dependencycheck.data.nvdcve.H2Functions.updateKnownExploited";

UPDATE Properties SET `value`='6.0' WHERE ID='version';
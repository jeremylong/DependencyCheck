DROP INDEX IF EXISTS idxVulnerability;
DROP INDEX IF EXISTS idxReference;
DROP INDEX IF EXISTS idxCpe;
DROP INDEX IF EXISTS idxCpeEntry;
DROP INDEX IF EXISTS idxSoftwareCve;
DROP INDEX IF EXISTS idxSoftwareCpe;
DROP TABLE IF EXISTS vulnerability;
DROP TABLE IF EXISTS reference;
DROP TABLE IF EXISTS cpeEntry;
DROP TABLE IF EXISTS software;
DROP TABLE IF EXISTS settings;

CREATE TABLE settings (id varchar(50) PRIMARY KEY, value varchar(200));

CREATE TABLE vulnerability (id int auto_increment PRIMARY KEY, cve VARCHAR(20) UNIQUE,
	description VARCHAR(8000), cwe VARCHAR(10), cvssScore DECIMAL(3,1), cvssAccessVector VARCHAR(20),
	cvssAccessComplexity VARCHAR(20), cvssAuthentication VARCHAR(20), cvssConfidentialityImpact VARCHAR(20),
	cvssIntegrityImpact VARCHAR(20), cvssAvailabilityImpact VARCHAR(20));

CREATE TABLE reference (cveid INT, name VARCHAR(1000), url VARCHAR(1000), source VARCHAR(255),
	CONSTRAINT fkReference FOREIGN KEY (cveid) REFERENCES vulnerability(id) ON DELETE CASCADE);

CREATE TABLE cpeEntry (id INT auto_increment PRIMARY KEY, cpe VARCHAR(500), vendor VARCHAR(255), product VARCHAR(255));

CREATE TABLE software (cveid INT, cpeEntryId INT, previousVersion VARCHAR(50)
    , CONSTRAINT fkSoftwareCve FOREIGN KEY (cveid) REFERENCES vulnerability(id) ON DELETE CASCADE
    , CONSTRAINT fkSoftwareCpeProduct FOREIGN KEY (cpeEntryId) REFERENCES cpeEntry(id));

CREATE INDEX idxVulnerability ON vulnerability(cve);
CREATE INDEX idxReference ON reference(cveid);
CREATE INDEX idxCpe ON cpeEntry(cpe);
CREATE INDEX idxCpeEntry ON cpeEntry(vendor, product);
CREATE INDEX idxSoftwareCve ON software(cveid);
CREATE INDEX idxSoftwareCpe ON software(cpeEntryId);

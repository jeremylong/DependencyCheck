DROP TABLE IF EXISTS software;
DROP TABLE IF EXISTS cpeEntry;
DROP TABLE IF EXISTS reference;
DROP TABLE IF EXISTS vulnerability;
DROP TABLE IF EXISTS properties;
DROP TABLE IF EXISTS cweEntry;
DROP TABLE IF EXISTS cpeEcosystemCache;
DROP ALIAS IF EXISTS update_vulnerability;
DROP ALIAS IF EXISTS insert_software;


CREATE TABLE vulnerability (id int auto_increment PRIMARY KEY, cve VARCHAR(20) UNIQUE,
	description VARCHAR(8000), v2Severity VARCHAR(20), v2ExploitabilityScore DECIMAL(3,1), 
        v2ImpactScore DECIMAL(3,1), v2AcInsufInfo BOOLEAN, v2ObtainAllPrivilege BOOLEAN, 
        v2ObtainUserPrivilege BOOLEAN, v2ObtainOtherPrivilege BOOLEAN, v2UserInteractionRequired BOOLEAN, 
        v2Score DECIMAL(3,1), v2AccessVector VARCHAR(20), v2AccessComplexity VARCHAR(20), 
        v2Authentication VARCHAR(20), v2ConfidentialityImpact VARCHAR(20), v2IntegrityImpact VARCHAR(20), 
        v2AvailabilityImpact VARCHAR(20), v2Version VARCHAR(5), v3ExploitabilityScore DECIMAL(3,1), 
        v3ImpactScore DECIMAL(3,1), v3AttackVector VARCHAR(20), v3AttackComplexity VARCHAR(20), 
        v3PrivilegesRequired VARCHAR(20), v3UserInteraction VARCHAR(20), v3Scope VARCHAR(20), 
        v3ConfidentialityImpact VARCHAR(20), v3IntegrityImpact VARCHAR(20), v3AvailabilityImpact VARCHAR(20), 
        v3BaseScore DECIMAL(3,1), v3BaseSeverity VARCHAR(20), v3Version VARCHAR(5));

CREATE TABLE reference (cveid INT, name VARCHAR(1000), url VARCHAR(1000), source VARCHAR(255),
	CONSTRAINT fkReference FOREIGN KEY (cveid) REFERENCES vulnerability(id) ON DELETE CASCADE);

CREATE TABLE cpeEntry (id INT auto_increment PRIMARY KEY, part CHAR(1), vendor VARCHAR(255), product VARCHAR(255),
version VARCHAR(255), update_version VARCHAR(255), edition VARCHAR(255), lang VARCHAR(20), sw_edition VARCHAR(255), 
target_sw VARCHAR(255), target_hw VARCHAR(255), other VARCHAR(255), ecosystem VARCHAR(255));

CREATE TABLE software (cveid INT, cpeEntryId INT, versionEndExcluding VARCHAR(60), versionEndIncluding VARCHAR(60),
                       versionStartExcluding VARCHAR(60), versionStartIncluding VARCHAR(60), vulnerable BOOLEAN
    , CONSTRAINT fkSoftwareCve FOREIGN KEY (cveid) REFERENCES vulnerability(id) ON DELETE CASCADE
    , CONSTRAINT fkSoftwareCpeProduct FOREIGN KEY (cpeEntryId) REFERENCES cpeEntry(id));

CREATE TABLE cweEntry (cveid INT, cwe VARCHAR(20),
    CONSTRAINT fkCweEntry FOREIGN KEY (cveid) REFERENCES vulnerability(id) ON DELETE CASCADE);

CREATE TABLE cpeEcosystemCache (vendor VARCHAR(255), product VARCHAR(255), ecosystem VARCHAR(255), PRIMARY KEY (vendor, product));
INSERT INTO cpeEcosystemCache (vendor, product, ecosystem) VALUES ('apache', 'zookeeper', 'MULTIPLE');
INSERT INTO cpeEcosystemCache (vendor, product, ecosystem) VALUES ('tensorflow', 'tensorflow', 'MULTIPLE');
INSERT INTO cpeEcosystemCache (vendor, product, ecosystem) VALUES ('scikit-learn', 'scikit-learn', 'MULTIPLE');

CREATE INDEX idxCwe ON cweEntry(cveid);
CREATE INDEX idxVulnerability ON vulnerability(cve);
CREATE INDEX idxReference ON reference(cveid);
CREATE INDEX idxSoftwareCve ON software(cveid);
CREATE INDEX idxSoftwareCpe ON software(cpeEntryId);
CREATE INDEX idxCpeEntry ON cpeEntry(part, vendor, product, version, update_version, edition, lang, sw_edition, target_sw, target_hw, other);
CREATE INDEX idxCpe ON cpeEntry(vendor, product);

CREATE ALIAS update_vulnerability FOR "org.owasp.dependencycheck.data.nvdcve.H2Functions.updateVulnerability";
CREATE ALIAS insert_software FOR "org.owasp.dependencycheck.data.nvdcve.H2Functions.insertSoftware";

CREATE TABLE properties (id varchar(50) PRIMARY KEY, value varchar(500));
INSERT INTO properties(id, value) VALUES ('version', '5.2');
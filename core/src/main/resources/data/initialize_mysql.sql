
#DROP USER 'dcuser';
#DROP database dependencycheck;

CREATE database dependencycheck;
USE dependencycheck;

DROP TABLE IF EXISTS software;
DROP TABLE IF EXISTS cpeEntry;
DROP TABLE IF EXISTS reference;
DROP TABLE IF EXISTS vulnerability;
DROP TABLE IF EXISTS properties;
DROP TABLE IF EXISTS cweEntry;

CREATE TABLE vulnerability (id int auto_increment PRIMARY KEY, cve VARCHAR(20) UNIQUE,
	description VARCHAR(8000), cvssV2Score DECIMAL(3,1), cvssV2AccessVector VARCHAR(20),
	cvssV2AccessComplexity VARCHAR(20), cvssV2Authentication VARCHAR(20), cvssV2ConfidentialityImpact VARCHAR(20),
	cvssV2IntegrityImpact VARCHAR(20), cvssV2AvailabilityImpact VARCHAR(20), cvssV2Severity VARCHAR(20),
        cvssV3AttackVector VARCHAR(20), cvssV3AttackComplexity VARCHAR(20), cvssV3PrivilegesRequired VARCHAR(20),
        cvssV3UserInteraction VARCHAR(20), cvssV3Scope VARCHAR(20), cvssV3ConfidentialityImpact VARCHAR(20),
        cvssV3IntegrityImpact VARCHAR(20), cvssV3AvailabilityImpact VARCHAR(20), cvssV3BaseScore DECIMAL(3,1), 
        cvssV3BaseSeverity VARCHAR(20));

CREATE TABLE reference (cveid INT, name VARCHAR(1000), url VARCHAR(1000), source VARCHAR(255),
	CONSTRAINT fkReference FOREIGN KEY (cveid) REFERENCES vulnerability(id) ON DELETE CASCADE);

CREATE TABLE cpeEntry (id INT auto_increment PRIMARY KEY, part CHAR(1), vendor VARCHAR(255), product VARCHAR(255),
version VARCHAR(255), update_version VARCHAR(255), edition VARCHAR(255), lang VARCHAR(20), sw_edition VARCHAR(255), 
target_sw VARCHAR(255), target_hw VARCHAR(255), other VARCHAR(255), ecosystem VARCHAR(255));

CREATE TABLE software (cveid INT, cpeEntryId INT, versionEndExcluding VARCHAR(50), versionEndIncluding VARCHAR(50), 
                       versionStartExcluding VARCHAR(50), versionStartIncluding VARCHAR(50), vulnerable BOOLEAN
    , CONSTRAINT fkSoftwareCve FOREIGN KEY (cveid) REFERENCES vulnerability(id) ON DELETE CASCADE
    , CONSTRAINT fkSoftwareCpeProduct FOREIGN KEY (cpeEntryId) REFERENCES cpeEntry(id));
    
CREATE TABLE cweEntry (cveid INT, cwe VARCHAR(20),
    CONSTRAINT fkCweEntry FOREIGN KEY (cveid) REFERENCES vulnerability(id) ON DELETE CASCADE);

CREATE INDEX idxCwe ON cweEntry(cveid);
CREATE INDEX idxVulnerability ON vulnerability(cve);
CREATE INDEX idxReference ON reference(cveid);
CREATE INDEX idxCpe ON cpeEntry(vendor, product);
CREATE INDEX idxSoftwareCve ON software(cveid);
CREATE INDEX idxSoftwareCpe ON software(cpeEntryId);

#on mysql we cannot index all columns due to key length issues
CREATE INDEX idxCpeEntry ON cpeEntry(part, vendor, product, version);
#, update_version, edition, lang, sw_edition, target_sw, target_hw, other);

CREATE TABLE properties (id varchar(50) PRIMARY KEY, value varchar(500));

DROP PROCEDURE IF EXISTS save_property;

DELIMITER //
CREATE PROCEDURE save_property
(IN prop varchar(50), IN val varchar(500))
BEGIN
INSERT INTO properties (`id`, `value`) VALUES (prop, val)
	ON DUPLICATE KEY UPDATE `value`=val;
END //
DELIMITER ;

GRANT EXECUTE ON PROCEDURE dependencycheck.save_property TO 'dcuser';

DELIMITER //
CREATE PROCEDURE update_ecosystems()
BEGIN
SET SQL_SAFE_UPDATES = 0;
UPDATE cpeEntry n INNER JOIN
    (SELECT DISTINCT vendor, product, MIN(ecosystem) eco
    FROM cpeEntry
    WHERE ecosystem IS NOT NULL
    GROUP BY vendor , product) e 
  ON e.vendor = n.vendor
  AND e.product = n.product 
SET n.ecosystem = e.eco
WHERE n.ecosystem IS NULL;
SET SQL_SAFE_UPDATES = 1;
END //
DELIMITER ;

GRANT EXECUTE ON PROCEDURE dependencycheck.update_ecosystems TO 'dcuser';

DELIMITER //
CREATE PROCEDURE cleanup_orphans()
BEGIN
SET SQL_SAFE_UPDATES = 0;
DELETE FROM cpeEntry WHERE id not in (SELECT CPEEntryId FROM software);
SET SQL_SAFE_UPDATES = 1;
END //
DELIMITER ;

GRANT EXECUTE ON PROCEDURE dependencycheck.cleanup_orphans TO 'dcuser';

INSERT INTO properties(id, value) VALUES ('version', '4.1');

-- DROP USER dcuser CASCADE;
-- CREATE USER dcuser IDENTIFIED BY "DC-Pass1337!";
-- GRANT UNLIMITED TABLESPACE TO dcuser;
-- GRANT CREATE SESSION to dcuser;

-- ALTER SESSION SET CURRENT_SCHEMA=dcuser;



BEGIN
  EXECUTE IMMEDIATE 'DROP SEQUENCE vulnerability_seq';
EXCEPTION
  WHEN OTHERS THEN
    IF SQLCODE != -2289 THEN
      RAISE;
    END IF;
END;
/

BEGIN
  EXECUTE IMMEDIATE 'DROP SEQUENCE cpeEntry_seq';
EXCEPTION
  WHEN OTHERS THEN
    IF SQLCODE != -2289 THEN
      RAISE;
    END IF;
END;
/

BEGIN
    EXECUTE IMMEDIATE 'DROP TABLE software CASCADE CONSTRAINTS';
EXCEPTION
    WHEN OTHERS THEN
        IF SQLCODE != -942 THEN
            RAISE;
        END IF;
END;
/

BEGIN
    EXECUTE IMMEDIATE 'DROP TABLE cpeEntry CASCADE CONSTRAINTS';
EXCEPTION
    WHEN OTHERS THEN
        IF SQLCODE != -942 THEN
            RAISE;
        END IF;
END;
/

BEGIN
    EXECUTE IMMEDIATE 'DROP TABLE reference CASCADE CONSTRAINTS';
EXCEPTION
    WHEN OTHERS THEN
        IF SQLCODE != -942 THEN
            RAISE;
        END IF;
END;
/

BEGIN
    EXECUTE IMMEDIATE 'DROP TABLE vulnerability CASCADE CONSTRAINTS';
EXCEPTION
    WHEN OTHERS THEN
        IF SQLCODE != -942 THEN
            RAISE;
        END IF;
END;
/

BEGIN
    EXECUTE IMMEDIATE 'DROP TABLE properties CASCADE CONSTRAINTS';
EXCEPTION
    WHEN OTHERS THEN
        IF SQLCODE != -942 THEN
            RAISE;
        END IF;
END;
/

BEGIN
    EXECUTE IMMEDIATE 'DROP TABLE cweEntry CASCADE CONSTRAINTS';
EXCEPTION
    WHEN OTHERS THEN
        IF SQLCODE != -942 THEN
            RAISE;
        END IF;
END;
/

BEGIN
    EXECUTE IMMEDIATE 'DROP TABLE cpeEcosystemCache CASCADE CONSTRAINTS';
EXCEPTION
    WHEN OTHERS THEN
        IF SQLCODE != -942 THEN
            RAISE;
        END IF;
END;
/

CREATE TABLE vulnerability (id INT NOT NULL PRIMARY KEY, cve VARCHAR(20) UNIQUE,
    description CLOB,
    v2Severity VARCHAR(20), v2ExploitabilityScore DECIMAL(3,1),
    v2ImpactScore DECIMAL(3,1), v2AcInsufInfo NUMBER(1), v2ObtainAllPrivilege NUMBER(1),
    v2ObtainUserPrivilege NUMBER(1), v2ObtainOtherPrivilege NUMBER(1), v2UserInteractionRequired NUMBER(1),
    v2Score DECIMAL(3,1), v2AccessVector VARCHAR(20), v2AccessComplexity VARCHAR(20),
    v2Authentication VARCHAR(20), v2ConfidentialityImpact VARCHAR(20), v2IntegrityImpact VARCHAR(20),
    v2AvailabilityImpact VARCHAR(20), v2Version VARCHAR(5),
    v3ExploitabilityScore DECIMAL(3,1),
    v3ImpactScore DECIMAL(3,1), v3AttackVector VARCHAR(20), v3AttackComplexity VARCHAR(20),
    v3PrivilegesRequired VARCHAR(20), v3UserInteraction VARCHAR(20), v3Scope VARCHAR(20),
    v3ConfidentialityImpact VARCHAR(20), v3IntegrityImpact VARCHAR(20), v3AvailabilityImpact VARCHAR(20),
    v3BaseScore DECIMAL(3,1), v3BaseSeverity VARCHAR(20), v3Version VARCHAR(5));

CREATE TABLE reference (cveid INT, name VARCHAR(1000), url VARCHAR(1000), source VARCHAR(255),
    CONSTRAINT fkReference FOREIGN KEY (cveid) REFERENCES vulnerability(id) ON DELETE CASCADE);

CREATE TABLE cpeEntry (id INT NOT NULL PRIMARY KEY, part CHAR(1), vendor VARCHAR(255), product VARCHAR(255),
version VARCHAR(255), update_version VARCHAR(255), edition VARCHAR(255), lang VARCHAR(20), sw_edition VARCHAR(255), 
target_sw VARCHAR(255), target_hw VARCHAR(255), other VARCHAR(255), ecosystem VARCHAR(255));

CREATE TABLE software (cveid INT, cpeEntryId INT, versionEndExcluding VARCHAR(60), versionEndIncluding VARCHAR(60), 
                       versionStartExcluding VARCHAR(60), versionStartIncluding VARCHAR(60), vulnerable number(1)
    , CONSTRAINT fkSoftwareCve FOREIGN KEY (cveid) REFERENCES vulnerability(id) ON DELETE CASCADE
    , CONSTRAINT fkSoftwareCpeProduct FOREIGN KEY (cpeEntryId) REFERENCES cpeEntry(id));

CREATE TABLE cweEntry (cveid INT, cwe VARCHAR(20),
    CONSTRAINT fkCweEntry FOREIGN KEY (cveid) REFERENCES vulnerability(id) ON DELETE CASCADE);

CREATE TABLE cpeEcosystemCache (vendor VARCHAR(255), product VARCHAR(255), ecosystem VARCHAR(255), PRIMARY KEY (vendor, product));
INSERT INTO cpeEcosystemCache (vendor, product, ecosystem) VALUES ('apache', 'zookeeper', 'MULTIPLE');
INSERT INTO cpeEcosystemCache (vendor, product, ecosystem) VALUES ('tensorflow', 'tensorflow', 'MULTIPLE');
INSERT INTO cpeEcosystemCache (vendor, product, ecosystem) VALUES ('scikit-learn', 'scikit-learn', 'MULTIPLE');

-- CREATE INDEX idxCwe ON cweEntry(cveid); -- PK automatically receives index
-- CREATE INDEX idxVulnerability ON vulnerability(cve); -- PK automatically receives index
CREATE INDEX idxReference ON reference(cveid);
CREATE INDEX idxCpe ON cpeEntry(vendor, product);
CREATE INDEX idxSoftwareCve ON software(cveid);
CREATE INDEX idxSoftwareCpe ON software(cpeEntryId);

CREATE UNIQUE INDEX idxCpeEntry ON cpeEntry(part, vendor, product, version, update_version, edition, lang, sw_edition, target_sw, target_hw, other);

CREATE TABLE properties (id varchar(50) PRIMARY KEY, value varchar(500));

CREATE SEQUENCE cpeEntry_seq;
CREATE SEQUENCE vulnerability_seq;

CREATE OR REPLACE TRIGGER VULNERABILITY_TRG
BEFORE INSERT
ON vulnerability
REFERENCING NEW AS New OLD AS Old
FOR EACH ROW
BEGIN
  :new.ID := vulnerability_seq.nextval;
END VULNERABILITY_TRG;
/

CREATE OR REPLACE TRIGGER CPEENTRY_TRG
BEFORE INSERT
ON cpeEntry
REFERENCING NEW AS New OLD AS Old
FOR EACH ROW
BEGIN
  :new.ID := cpeEntry_seq.nextval;
END CPEENTRY_TRG;
/

CREATE OR REPLACE PROCEDURE save_property(prop IN properties.id%type, val IN properties.value%type) AS
BEGIN
    INSERT INTO properties (id, value) VALUES (prop, val);
EXCEPTION
    WHEN DUP_VAL_ON_INDEX THEN
        UPDATE properties SET value=val WHERE id=prop;
END;
/

GRANT EXECUTE ON save_property TO dcuser;


CREATE OR REPLACE PROCEDURE merge_ecosystem(p_vendor IN cpeEcosystemCache.vendor%type, p_product IN cpeEcosystemCache.product%type, p_ecosystem IN cpeEcosystemCache.ecosystem%type) AS
BEGIN
    INSERT INTO cpeEcosystemCache (vendor, product, ecosystem) VALUES (p_vendor, p_product, p_ecosystem);
EXCEPTION
    WHEN DUP_VAL_ON_INDEX THEN
        UPDATE cpeEcosystemCache SET ecosystem=p_ecosystem WHERE product=p_product AND vendor=p_vendor;
END;
/

GRANT EXECUTE ON merge_ecosystem TO dcuser;

CREATE OR REPLACE PROCEDURE update_vulnerability(p_cveId IN vulnerability.cve%type,
                                      p_description IN vulnerability.description%type,
                                      p_v2Severity IN vulnerability.v2Severity%type,
                                      p_v2ExploitabilityScore IN vulnerability.v2ExploitabilityScore%type,
                                      p_v2ImpactScore IN vulnerability.v2ImpactScore%type,
                                      p_v2AcInsufInfo IN vulnerability.v2AcInsufInfo%type,
                                      p_v2ObtainAllPrivilege IN vulnerability.v2ObtainAllPrivilege%type,
                                      p_v2ObtainUserPrivilege IN vulnerability.v2ObtainUserPrivilege%type,
                                      p_v2ObtainOtherPrivilege IN vulnerability.v2ObtainOtherPrivilege%type,
                                      p_v2UserInteractionRequired IN vulnerability.v2UserInteractionRequired%type,
                                      p_v2Score IN vulnerability.v2Score%type,
                                      p_v2AccessVector IN vulnerability.v2AccessVector%type,
                                      p_v2AccessComplexity IN vulnerability.v2AccessComplexity%type,
                                      p_v2Authentication IN vulnerability.v2Authentication%type,
                                      p_v2ConfidentialityImpact IN vulnerability.v2ConfidentialityImpact%type,
                                      p_v2IntegrityImpact IN vulnerability.v2IntegrityImpact%type,
                                      p_v2AvailabilityImpact IN vulnerability.v2AvailabilityImpact%type,
                                      p_v2Version IN vulnerability.v2Version%type,
                                      p_v3ExploitabilityScore IN vulnerability.v3ExploitabilityScore%type,
                                      p_v3ImpactScore IN vulnerability.v3ImpactScore%type,
                                      p_v3AttackVector IN vulnerability.v3AttackVector%type,
                                      p_v3AttackComplexity IN vulnerability.v3AttackComplexity%type,
                                      p_v3PrivilegesRequired IN vulnerability.v3PrivilegesRequired%type,
                                      p_v3UserInteraction IN vulnerability.v3UserInteraction%type,
                                      p_v3Scope IN vulnerability.v3Scope%type,
                                      p_v3ConfidentialityImpact IN vulnerability.v3ConfidentialityImpact%type,
                                      p_v3IntegrityImpact IN vulnerability.v3IntegrityImpact%type,
                                      p_v3AvailabilityImpact IN vulnerability.v3AvailabilityImpact%type,
                                      p_v3BaseScore IN vulnerability.v3BaseScore%type,
                                      p_v3BaseSeverity IN vulnerability.v3BaseSeverity%type,
                                      p_v3Version IN vulnerability.v3Version%type,
                                      vulnerabilityId OUT vulnerability.id%type)
                                       AS
BEGIN
    BEGIN
        SELECT id into vulnerabilityId FROM vulnerability WHERE cve = p_cveId;
        DELETE FROM reference WHERE cveid = vulnerabilityId;
        DELETE FROM software WHERE cveid = vulnerabilityId;
        DELETE FROM cweEntry WHERE cveid = vulnerabilityId;
        UPDATE vulnerability
        SET description=p_description,
            v2Severity=p_v2Severity,
            v2ExploitabilityScore=p_v2ExploitabilityScore,
            v2ImpactScore=p_v2ImpactScore,
            v2AcInsufInfo=p_v2AcInsufInfo,
            v2ObtainAllPrivilege=p_v2ObtainAllPrivilege,
            v2ObtainUserPrivilege=p_v2ObtainUserPrivilege,
            v2ObtainOtherPrivilege=p_v2ObtainOtherPrivilege,
            v2UserInteractionRequired=p_v2UserInteractionRequired,
            v2Score=p_v2Score,
            v2AccessVector=p_v2AccessVector,
            v2AccessComplexity=p_v2AccessComplexity,
            v2Authentication=p_v2Authentication,
            v2ConfidentialityImpact=p_v2ConfidentialityImpact,
            v2IntegrityImpact=p_v2IntegrityImpact,
            v2AvailabilityImpact=p_v2AvailabilityImpact,
            v2Version=p_v2Version,
            v3ExploitabilityScore=p_v3ExploitabilityScore,
            v3ImpactScore=p_v3ImpactScore,
            v3AttackVector=p_v3AttackVector,
            v3AttackComplexity=p_v3AttackComplexity,
            v3PrivilegesRequired=p_v3PrivilegesRequired,
            v3UserInteraction=p_v3UserInteraction,
            v3Scope=p_v3Scope,
            v3ConfidentialityImpact=p_v3ConfidentialityImpact,
            v3IntegrityImpact=p_v3IntegrityImpact,
            v3AvailabilityImpact=p_v3AvailabilityImpact,
            v3BaseScore=p_v3BaseScore,
            v3BaseSeverity=p_v3BaseSeverity,
            v3Version=p_v3Version
        WHERE id = vulnerabilityId;
    EXCEPTION
        WHEN NO_DATA_FOUND THEN
            INSERT INTO vulnerability (cve, description,
                                       v2Severity, v2ExploitabilityScore,
                                       v2ImpactScore, v2AcInsufInfo, v2ObtainAllPrivilege,
                                       v2ObtainUserPrivilege, v2ObtainOtherPrivilege, v2UserInteractionRequired,
                                       v2Score, v2AccessVector, v2AccessComplexity,
                                       v2Authentication, v2ConfidentialityImpact, v2IntegrityImpact,
                                       v2AvailabilityImpact, v2Version, v3ExploitabilityScore,
                                       v3ImpactScore, v3AttackVector, v3AttackComplexity,
                                       v3PrivilegesRequired, v3UserInteraction, v3Scope,
                                       v3ConfidentialityImpact, v3IntegrityImpact, v3AvailabilityImpact,
                                       v3BaseScore, v3BaseSeverity, v3Version)
            VALUES (p_cveId, p_description,
                    p_v2Severity, p_v2ExploitabilityScore,
                    p_v2ImpactScore, p_v2AcInsufInfo, p_v2ObtainAllPrivilege,
                    p_v2ObtainUserPrivilege, p_v2ObtainOtherPrivilege, p_v2UserInteractionRequired,
                    p_v2Score, p_v2AccessVector, p_v2AccessComplexity,
                    p_v2Authentication, p_v2ConfidentialityImpact, p_v2IntegrityImpact,
                    p_v2AvailabilityImpact, p_v2Version, p_v3ExploitabilityScore,
                    p_v3ImpactScore, p_v3AttackVector, p_v3AttackComplexity,
                    p_v3PrivilegesRequired, p_v3UserInteraction, p_v3Scope,
                    p_v3ConfidentialityImpact, p_v3IntegrityImpact, p_v3AvailabilityImpact,
                    p_v3BaseScore, p_v3BaseSeverity, p_v3Version)
            RETURNING id INTO vulnerabilityId;
        WHEN OTHERS THEN
            RAISE;
    END;
END;
/

GRANT EXECUTE ON update_vulnerability TO dcuser;

CREATE OR REPLACE PROCEDURE insert_software(p_vulnerabilityId IN software.cveid%type,
                                 p_part IN cpeEntry.part%type,
                                 p_vendor IN cpeEntry.vendor%type,
                                 p_product IN cpeEntry.product%type,
                                 p_version IN cpeEntry.version%type,
                                 p_update_version IN cpeEntry.update_version%type,
                                 p_edition IN cpeEntry.edition%type,
                                 p_lang IN cpeEntry.lang%type,
                                 p_sw_edition IN cpeEntry.sw_edition%type,
                                 p_target_sw IN cpeEntry.target_sw%type,
                                 p_target_hw IN cpeEntry.target_hw%type,
                                 p_other IN cpeEntry.other%type,
                                 p_ecosystem IN cpeEntry.ecosystem%type,
                                 p_versionEndExcluding IN software.versionEndExcluding%type,
                                 p_versionEndIncluding IN software.versionEndIncluding%type,
                                 p_versionStartExcluding IN software.versionStartExcluding%type,
                                 p_versionStartIncluding IN software.versionStartIncluding%type,
                                 p_vulnerable IN software.vulnerable%type) AS
    cpeId cpeEntry.id%type;
    currentEcosystem cpeEntry.ecosystem%type;
BEGIN
    BEGIN
        SELECT id, ecosystem
        INTO cpeId, currentEcosystem
        FROM cpeEntry
        WHERE part = p_part
          AND vendor = p_vendor
          AND product = p_product
          AND version = p_version
          AND update_version = p_update_version
          AND edition = p_edition
          AND lang = p_lang
          AND sw_edition = p_sw_edition
          AND target_sw = p_target_sw
          AND target_hw = p_target_hw
          AND other = p_other;
    EXCEPTION
        WHEN NO_DATA_FOUND THEN
           cpeId := 0;
           currentEcosystem := NULL;
        WHEN OTHERS THEN
           RAISE;
    END;

    IF cpeId > 0 THEN
        IF currentEcosystem IS NULL AND p_ecosystem IS NOT NULL THEN
            UPDATE cpeEntry SET ecosystem=p_ecosystem WHERE id = cpeId;
        END IF;
    ELSE
        INSERT INTO cpeEntry (part,
                              vendor,
                              product,
                              version,
                              update_version,
                              edition,
                              lang,
                              sw_edition,
                              target_sw,
                              target_hw,
                              other,
                              ecosystem)
        VALUES (p_part,
                p_vendor,
                p_product,
                p_version,
                p_update_version,
                p_edition,
                p_lang,
                p_sw_edition,
                p_target_sw,
                p_target_hw,
                p_other,
                p_ecosystem)
        RETURNING id INTO cpeId;
    END IF;

    INSERT INTO software (cveid,
                          cpeEntryId,
                          versionEndExcluding,
                          versionEndIncluding,
                          versionStartExcluding,
                          versionStartIncluding,
                          vulnerable)
    VALUES (p_vulnerabilityId,
            cpeId,
            p_versionEndExcluding,
            p_versionEndIncluding,
            p_versionStartExcluding,
            p_versionStartIncluding,
            p_vulnerable);

END;
/

GRANT EXECUTE ON insert_software TO dcuser;

CREATE OR REPLACE VIEW v_update_ecosystems AS
    SELECT e.ecosystem AS entryEco, c.ecosystem AS cachedEco
    FROM cpeEntry e INNER JOIN cpeEcosystemCache c
    ON c.vendor=e.vendor
        AND c.product=e.product;

INSERT INTO properties(id,value) VALUES ('version','5.2');

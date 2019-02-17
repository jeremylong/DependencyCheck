ALTER TABLE cpeEntry ADD COLUMN part CHAR(1);
UPDATE cpeEntry SET part='a';
CREATE INDEX idxCpeEntry ON cpeEntry(part, vendor, product, version, update_version, edition, lang, sw_edition, target_sw, target_hw, other);

ALTER TABLE cpeEntry ADD COLUMN ecosystem VARCHAR(255);

UPDATE Properties SET value='4.1' WHERE ID='version';

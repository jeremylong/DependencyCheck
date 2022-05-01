UPDATE cpeEcosystemCache set ecosystem='MULTIPLE' where vendor = 'icu-project' and product = 'international_components_for_unicode';
INSERT INTO cpeEcosystemCache (vendor, product, ecosystem) VALUES ('unicode', 'international_components_for_unicode', 'MULTIPLE');

UPDATE Properties SET `value`='5.2.1' WHERE ID='version';
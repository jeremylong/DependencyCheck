UPDATE cpeecosystemcache SET ecosystem='MULTIPLE' WHERE vendor='tensorflow' AND product='tensorflow';

UPDATE cpeecosystemcache SET ecosystem='MULTIPLE' WHERE vendor='scikit-learn' AND product='scikit-learn';

UPDATE Properties SET `value`='5.1' WHERE ID='version';

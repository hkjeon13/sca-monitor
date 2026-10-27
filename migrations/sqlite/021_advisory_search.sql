CREATE INDEX idx_advisories_package_lookup ON advisories(canonical_package_name,ecosystem);

-- External content keeps the original advisory rows authoritative.
CREATE VIRTUAL TABLE advisory_search USING fts5(
    advisory_id, summary, package_name,
    content='advisories', content_rowid='rowid', tokenize='unicode61'
);
INSERT INTO advisory_search(advisory_search) VALUES('rebuild');

CREATE TRIGGER advisory_search_insert AFTER INSERT ON advisories BEGIN
    INSERT INTO advisory_search(rowid,advisory_id,summary,package_name)
    VALUES(new.rowid,new.advisory_id,new.summary,new.package_name);
END;
CREATE TRIGGER advisory_search_delete AFTER DELETE ON advisories BEGIN
    INSERT INTO advisory_search(advisory_search,rowid,advisory_id,summary,package_name)
    VALUES('delete',old.rowid,old.advisory_id,old.summary,old.package_name);
END;
CREATE TRIGGER advisory_search_update AFTER UPDATE ON advisories
WHEN old.advisory_id IS NOT new.advisory_id OR old.summary IS NOT new.summary
    OR old.package_name IS NOT new.package_name
BEGIN
    INSERT INTO advisory_search(advisory_search,rowid,advisory_id,summary,package_name)
    VALUES('delete',old.rowid,old.advisory_id,old.summary,old.package_name);
    INSERT INTO advisory_search(rowid,advisory_id,summary,package_name)
    VALUES(new.rowid,new.advisory_id,new.summary,new.package_name);
END;

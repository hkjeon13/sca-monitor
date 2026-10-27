CREATE INDEX idx_advisories_package_lookup ON advisories(canonical_package_name,ecosystem);
CREATE INDEX idx_advisory_search ON advisories USING GIN(
    to_tsvector('simple',advisory_id || ' ' || summary || ' ' || package_name)
);

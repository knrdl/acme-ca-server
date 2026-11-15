-- support IP addresses as ACME identifiers.
-- the column stored a domain_name (FQDN) value and rejected IP addresses.
-- identifiers (domain or IP) are validated by the application, so relax the column to plain text.
alter table authorizations alter column domain type text using domain::text;

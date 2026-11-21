-- support IP addresses as ACME identifiers
alter table authorizations rename column domain to identifier_value;
alter table authorizations rename constraint authorizations_domain_lowercase to authorizations_identifier_value_lowercase;

alter table authorizations alter column identifier_value type text using identifier_value::text;

alter table authorizations
    add column identifier_type text not null default 'dns',
    add constraint authorizations_identifier_type_check check (identifier_type in ('dns', 'ip'));

alter table authorizations
    add constraint authorizations_identifier_value_check check (
        (identifier_type = 'dns' and identifier_value ~ '^.+\.[^\.]+$')
        or (identifier_type = 'ip' and (identifier_value ~ ':' or identifier_value ~ '^\d{1,3}(\.\d{1,3}){3}$'))
    );
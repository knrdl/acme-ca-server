update authorizations set domain = lower(domain) where domain <> lower(domain);

alter table authorizations add constraint authorizations_domain_lowercase check (domain = lower(domain));

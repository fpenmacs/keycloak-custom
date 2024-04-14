GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO postgres;

create table public.users
(
    id                          varchar(36)           not null
        constraint constraint_fb
            primary key,
    email                       varchar(255),
    email_constraint            varchar(255),
    email_verified              boolean default false not null,
    enabled                     boolean default false not null,
    federation_link             varchar(255),
    firstName                  varchar(255),
    lastName                   varchar(255),
    realm_id                    varchar(255),
    username                    varchar(255),
    fullName                    varchar(255),
    hash_pwd                    varchar(255),
    cpf                         varchar(255),
    created_timestamp           bigint,
    service_account_client_link varchar(255),
    not_before                  integer default 0     not null,
    constraint uk_dykn684sl8up1crfei6eckhd7
        unique (realm_id, email_constraint),
    constraint uk_ru8tt6t700s9v50bu18ws5ha6
        unique (realm_id, username)
);



alter table public.users
    owner to postgres;

create index idx_user_email
    on public.users (email);

create index idx_user_service_account
    on public.users (realm_id, service_account_client_link);


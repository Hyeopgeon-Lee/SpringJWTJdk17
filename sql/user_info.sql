create table USER_INFO
(
    USER_ID   varchar(100)  not null
        primary key,
    USER_NAME varchar(100)  null,
    PASSWORD  varchar(100)  null,
    EMAIL     varchar(100)  null,
    ADDR1     varchar(4000) null,
    ADDR2     varchar(4000) null,
    ROLES     varchar(100)  null,
    REG_ID    varchar(100)  null,
    REG_DT    datetime      null,
    CHG_ID    varchar(100)  null,
    CHG_DT    datetime      null
);
create table NOTICE
(
    NOTICE_SEQ int auto_increment
        primary key,
    TITLE      varchar(1000) null,
    CONTENTS   varchar(4000) null,
    NOTICE_YN  varchar(100)  null,
    READ_CNT   int           null,
    USER_ID    varchar(100)  null,
    REG_ID     varchar(100)  null,
    REG_DT     datetime      null,
    CHG_ID     varchar(100)  null,
    CHG_DT     datetime      null
);
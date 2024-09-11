
# DB 생성
create database myDB;

use mysql;

# 계정 생성
create user 'poly'@'%' identified by '1234';

grant all privileges on myDB.* to 'poly'@'%';

flush privileges;

show grants for 'poly'@'%';


CREATE USER 'password_manager'@'localhost' IDENTIFIED BY '843gfbwufb239eubswsfhsife';
GRANT ALL PRIVILEGES ON * . * TO 'password_manager'@'localhost';

CREATE DATABASE PASSWORD_MANAGER;
USE PASSWORD_MANAGER;

CREATE TABLE USERS(
    USERNAME VARCHAR(25) NOT NULL,
    HASHED_PASSWORD CHAR(87) NOT NULL,
    PRIMARY KEY(USERNAME)
);

CREATE TABLE PASSWORDS(
    ID INT NOT NULL AUTO_INCREMENT,
    NAME_OF_PASSWORD VARCHAR(25) NOT NULL,
    VALUE_OF_PASSWORD VARCHAR(127) NOT NULL,
    OWNER_OF_PASSWORD VARCHAR(25) NOT NULL,
    PRIMARY KEY(ID),
    FOREIGN KEY(OWNER_OF_PASSWORD) REFERENCES USERS(USERNAME)
);

CREATE TABLE SHARES(
    ID INT NOT NULL AUTO_INCREMENT,
    ID_OF_PASSWORD INT NOT NULL,
    SHARED_TO VARCHAR(25) NOT NULL,
    PRIMARY KEY(ID),
    FOREIGN KEY(ID_OF_PASSWORD) REFERENCES PASSWORDS(ID),
    FOREIGN KEY(SHARED_TO) REFERENCES USERS(USERNAME)
);
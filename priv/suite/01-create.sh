#!/bin/bash

# OpenLDAP tests

ldapadd -H ldap://localhost:1489 -x -D "cn=admin,cn=config"       -w secret -c -f ssl-mac.ldif
ldapadd -H ldap://localhost:1489 -x -D "cn=admin,dc=synrc,dc=com" -w secret -c -f synrc.com.ldif
ldapadd -H ldap://localhost:1489 -x -D "cn=admin,dc=synrc,dc=com" -w secret -c -f add.ldif
ldapadd -H ldap://localhost:1489 -x -D "cn=admin,dc=synrc,dc=com" -w secret -c -f add-exists.ldif
ldapadd -H ldap://localhost:1489 -x -D "cn=admin,dc=synrc,dc=com" -w secret -c -f modify-replace.ldif
ldapadd -H ldap://localhost:1489 -x -D "cn=admin,dc=synrc,dc=com" -w secret -c -f modify-add.ldif
ldapadd -H ldap://localhost:1489 -x -D "cn=admin,dc=synrc,dc=com" -w secret -c -f modify-del.ldif
ldapadd -H ldap://localhost:1489 -x -D "cn=admin,dc=synrc,dc=com" -w secret -c -f modify-multi.ldif
ldapadd -H ldap://localhost:1489 -x -D "cn=admin,dc=synrc,dc=com" -w secret -c -f modify-noobj.ldif
ldapadd -H ldap://localhost:1489 -x -D "cn=admin,dc=synrc,dc=com" -w secret -c -f modify-dn.ldif
ldapadd -H ldap://localhost:1489 -x -D "cn=admin,dc=synrc,dc=com" -w secret -c -f delete.ldif
ldapadd -H ldap://localhost:1489 -x -D "cn=admin,dc=synrc,dc=com" -w secret -c -f delete-noobj.ldif

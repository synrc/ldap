#!/bin/bash

# OpenLDAP tests

ldapsearch -H ldap://localhost:1489 -D "cn=admin,cn=config"       -w secret -b "cn=config"
ldapsearch -H ldap://localhost:1489 -D "cn=admin,dc=synrc,dc=com" -w secret -b "dc=synrc,dc=com"
ldapsearch -H ldap://localhost:1489 -D "cn=admin,dc=synrc,dc=com" -w secret -b "ou=People,dc=synrc,dc=com"
ldapsearch -H ldap://localhost:1489 -D "cn=admin,dc=synrc,dc=com" -w secret -b "ou=People,dc=synrc,dc=com" "uid=*" "objectClass"
ldapsearch -H ldap://localhost:1489 -D "cn=admin,dc=synrc,dc=com" -w secret -b "ou=People,dc=synrc,dc=com" '(sn=*To*)' cn sn
ldapcompare -H ldap://localhost:1489 -D "cn=admin,dc=synrc,dc=com" -w secret cn=admin,dc=synrc,dc=com cn:admin

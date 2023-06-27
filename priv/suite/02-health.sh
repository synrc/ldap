#!/bin/bash

# OpenLDAP tests

ldapsearch  -D "cn=admin,cn=config"       -w secret -b "cn=config"
ldapsearch  -D "cn=admin,dc=synrc,dc=com" -w secret -b "dc=synrc,dc=com"
ldapsearch  -D "cn=admin,dc=synrc,dc=com" -w secret -b "ou=People,dc=synrc,dc=com"
ldapsearch  -D "cn=admin,dc=synrc,dc=com" -w secret -b "ou=People,dc=synrc,dc=com" "uid=*" "objectClass"
ldapsearch  -D "cn=admin,dc=synrc,dc=com" -w secret -b "ou=People,dc=synrc,dc=com" '(sn=To*)' cn sn
ldapcompare -D "cn=admin,dc=synrc,dc=com" -w secret uid=admin,dc=synrc,dc=com uid:admin

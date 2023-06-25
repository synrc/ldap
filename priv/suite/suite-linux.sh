#!/bin/bash

# OpenLDAP tests

ldapsearch -D "cn=admin,cn=config" -w secret -b "cn=config" -Y EXTERNAL -H ldapi:///
ldapsearch -D "cn=admin,dc=synrc,dc=com" -w secret -b "dc=synrc,dc=com"  -Y EXTERNAL -H ldapi:///
ldapsearch -D "cn=admin,dc=synrc,dc=com" -w secret -b "ou=People,dc=synrc,dc=com" -Y EXTERNAL -H ldapi:/// "(&(uid=*)(sn=Ton*))"
ldapsearch -D "cn=admin,dc=synrc,dc=com" -w secret -b "ou=People,dc=synrc,dc=com" -Y EXTERNAL -H ldapi:/// "uid=*" "objectClass"
ldapsearch -D "cn=admin,dc=synrc,dc=com" -w secret -b "ou=People,dc=synrc,dc=com" -Y EXTERNAL -H ldapi:/// '(sn=To*)' cn sn 
ldapcompare -D "cn=admin,dc=synrc,dc=com" -w secret  -Y EXTERNAL -H ldapi:/// uid=admin,dc=synrc,dc=com uid:admin 

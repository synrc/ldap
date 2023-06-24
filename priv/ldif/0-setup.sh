#!/bin/bash

# OpenLDAP tests

ldapadd -x -D "cn=Manager,dc=synrc,dc=com" -w secret -c -f init.ldif
ldapadd -x -D "cn=Manager,dc=synrc,dc=com" -w secret -c -f add.ldif
ldapadd -x -D "cn=Manager,dc=synrc,dc=com" -w secret -c -f add-exists.ldif
ldapadd -x -D "cn=Manager,dc=synrc,dc=com" -w secret -c -f modify-replace.ldif
ldapadd -x -D "cn=Manager,dc=synrc,dc=com" -w secret -c -f modify-add.ldif
ldapadd -x -D "cn=Manager,dc=synrc,dc=com" -w secret -c -f modify-del.ldif
ldapadd -x -D "cn=Manager,dc=synrc,dc=com" -w secret -c -f modify-multi.ldif
ldapadd -x -D "cn=Manager,dc=synrc,dc=com" -w secret -c -f modify-noobj.ldif
ldapadd -x -D "cn=Manager,dc=synrc,dc=com" -w secret -c -f modify-dn.ldif
ldapadd -x -D "cn=Manager,dc=synrc,dc=com" -w secret -c -f delete.ldif
ldapadd -x -D "cn=Manager,dc=synrc,dc=com" -w secret -c -f delete-noobj.ldif

ldapsearch -D "cn=Manager,dc=synrc,dc=com" -w secret -b "dc=synrc,dc=com"
ldapsearch -D "cn=Manager,dc=synrc,dc=com" -w secret -b "ou=People,dc=synrc,dc=com" "(&(uid=*)(sn=Ton*))"
ldapsearch -D "cn=Manager,dc=synrc,dc=com" -w secret -b "ou=People,dc=synrc,dc=com" "uid=*" "objectClass"
ldapsearch -D "cn=Manager,dc=synrc,dc=com" -w secret -b "ou=People,dc=synrc,dc=com" '(sn=To*)' cn sn

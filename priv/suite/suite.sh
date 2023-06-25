#!/bin/bash

# OpenLDAP tests

ldapadd -x -D "cn=admin,dc=synrc,dc=com" -w secret -c -f init.ldif 
ldapadd -x -D "cn=admin,dc=synrc,dc=com" -w secret -c -f add.ldif 
ldapadd -x -D "cn=admin,dc=synrc,dc=com" -w secret -c -f add-exists.ldif 
ldapadd -x -D "cn=admin,dc=synrc,dc=com" -w secret -c -f modify-replace.ldif 
ldapadd -x -D "cn=admin,dc=synrc,dc=com" -w secret -c -f modify-add.ldif 
ldapadd -x -D "cn=admin,dc=synrc,dc=com" -w secret -c -f modify-del.ldif 
ldapadd -x -D "cn=admin,dc=synrc,dc=com" -w secret -c -f modify-multi.ldif 
ldapadd -x -D "cn=admin,dc=synrc,dc=com" -w secret -c -f modify-noobj.ldif 
ldapadd -x -D "cn=admin,dc=synrc,dc=com" -w secret -c -f modify-dn.ldif 
ldapadd -x -D "cn=admin,dc=synrc,dc=com" -w secret -c -f delete.ldif 
ldapadd -x -D "cn=admin,dc=synrc,dc=com" -w secret -c -f delete-noobj.ldif 

ldapsearch -D "cn=admin,cn=config" -w secret -b "cn=config" -Y EXTERNAL -H ldapi:///
ldapsearch -D "cn=admin,dc=synrc,dc=com" -w secret -b "dc=synrc,dc=com"  -Y EXTERNAL -H ldapi:///
ldapsearch -D "cn=admin,dc=synrc,dc=com" -w secret -b "ou=People,dc=synrc,dc=com" -Y EXTERNAL -H ldapi:/// "(&(uid=*)(sn=Ton*))"
ldapsearch -D "cn=admin,dc=synrc,dc=com" -w secret -b "ou=People,dc=synrc,dc=com" -Y EXTERNAL -H ldapi:/// "uid=*" "objectClass"
ldapsearch -D "cn=admin,dc=synrc,dc=com" -w secret -b "ou=People,dc=synrc,dc=com" -Y EXTERNAL -H ldapi:/// '(sn=To*)' cn sn 
ldapcompare -D "cn=admin,dc=synrc,dc=com" -w secret  -Y EXTERNAL -H ldapi:/// uid=admin,dc=synrc,dc=com uid:admin 

SYNRC 🌐 LDAP
=============
[![Hex pm](http://img.shields.io/hexpm/v/ldap.svg?style=flat)](https://hex.pm/packages/ldap)

SYNRC LDAP is a high-performance LDAP directory server with MNESIA backend.

![ldap-shaders](https://github.com/synrc/ldap/assets/144776/19f35667-9a0e-4e43-8524-b6ccdf6c21b7)

Create
------

```
$ ldapadd -x -D "cn=Manager,dc=synrc,dc=com" -w secret -c -f init.ldif
$ ldapadd -x -D "cn=Manager,dc=synrc,dc=com" -w secret -c -f add.ldif
$ ldapadd -x -D "cn=Manager,dc=synrc,dc=com" -w secret -c -f add-exists.ldif
```

Modify
------

```
$ ldapadd -x -D "cn=Manager,dc=synrc,dc=com" -w secret -c -f modify-replace.ldif
$ ldapadd -x -D "cn=Manager,dc=synrc,dc=com" -w secret -c -f modify-add.ldif
$ ldapadd -x -D "cn=Manager,dc=synrc,dc=com" -w secret -c -f modify-del.ldif
$ ldapadd -x -D "cn=Manager,dc=synrc,dc=com" -w secret -c -f modify-multi.ldif
$ ldapadd -x -D "cn=Manager,dc=synrc,dc=com" -w secret -c -f modify-noobj.ldif
$ ldapadd -x -D "cn=Manager,dc=synrc,dc=com" -w secret -c -f modify-dn.ldif
```

Delete
------

```
$ ldapadd -x -D "cn=Manager,dc=synrc,dc=com" -w secret -c -f delete.ldif
$ ldapadd -x -D "cn=Manager,dc=synrc,dc=com" -w secret -c -f delete-noobj.ldif
```

Search
------

```
$ ldapsearch -D "cn=admin,cn=config" -w secret -b "cn=config"
$ ldapsearch -D "uid=admin,dc=synrc,dc=com" -w secret -b "dc=synrc,dc=com"
$ ldapsearch -D "uid=admin,dc=synrc,dc=com" -w secret -b "ou=People,dc=synrc,dc=com" "(&(uid=*)(sn=Ton*))"
$ ldapsearch -D "uid=admin,dc=synrc,dc=com" -w secret -b "ou=People,dc=synrc,dc=com" "uid=*" "objectClass"
$ ldapsearch -D "uid=admin,dc=synrc,dc=com" -w secret -b "ou=People,dc=synrc,dc=com" '(sn=To*)' cn sn
```

Compare
-------

```
$ ldapcompare "uid=admin,dc=synrc,dc=com" uid:admin -h localhost -p 1389 -D "uid=admin,dc=synrc,dc=com" -w secret
> TRUE
```

Credits
-------

* Maxim Sokhatsky

SYNRC 📇 LDAP
=============

SYNRC LDAP is a high-performance LDAP directory server with MNESIA backend.

![ldap-shaders](https://github.com/synrc/ldap/assets/144776/19f35667-9a0e-4e43-8524-b6ccdf6c21b7)


Search
------

```
$ ldapsearch -b "dc=synrc,dc=com" 'objectClass=*' -h localhost -p 1389 -D "uid=admin,dc=synrc,dc=com" -w secret
$ ldapsearch -b "dc=synrc,dc=com" '(&(uid=*)(cn=Ma*))' -h localhost -p 1389 -D "uid=admin,dc=synrc,dc=com" -w secret
$ ldapsearch -b "dc=synrc,dc=com" 'sn=*' cn sn -h localhost -p 1389 -D "uid=admin,dc=synrc,dc=com" -w secret
$ ldapsearch -b "dc=synrc,dc=com" 'sn=*' cn sn -z 1 -h localhost -p 1389 -D "uid=admin,dc=synrc,dc=com" -w secret
```

Create
------

```
$ ldapmodify -f t/010-add.ldif -h localhost -p 1389 -D "uid=admin,dc=synrc,dc=com" -w secret
> adding new entry "cn=alice,ou=People,dc=synrc,dc=com"
> adding new entry "cn=bob,ou=People,dc=synrc,dc=com"
$ ldapmodify -f t/011-add-exists.ldif -h localhost -p 1389 -D "uid=admin,dc=synrc,dc=com" -w secret
> adding new entry "cn=alice,ou=People,dc=synrc,dc=com"
> ldap_add: Already exists (68)
```

Modify
------

```
$ ldapmodify -f t/020-modify-replace.ldif -h localhost -p 1389 -D "uid=admin,dc=synrc,dc=com" -w secret
$ modifying entry "cn=alice,ou=People,dc=synrc,dc=com"
$ ldapmodify -f t/021-modify-add.ldif -h localhost -p 1389 -D "uid=admin,dc=synrc,dc=com" -w secret
> modifying entry "cn=alice,ou=People,dc=synrc,dc=com"
$ ldapmodify -f t/022-modify-del.ldif -h localhost -p 1389 -D "uid=admin,dc=synrc,dc=com" -w secret
> modifying entry "cn=bob,ou=People,dc=synrc,dc=com"
$ ldapmodify -f t/023-modify-multi.ldif -h localhost -p 1389 -D "uid=admin,dc=synrc,dc=com" -w secret
> modifying entry "cn=bob,ou=People,dc=synrc,dc=com"
$ ldapmodify -f t/024-modify-noobj.ldif -h localhost -p 1389 -D "uid=admin,dc=synrc,dc=com" -w secret
> modifying entry "cn=eve,ou=People,dc=synrc,dc=com"
> ldap_modify: No such object (32)
$ ldapmodify -f t/025-modify-dn.ldif -h localhost -p 1389 -D "uid=admin,dc=synrc,dc=com" -w secret
> modifying rdn of entry "cn=alice,ou=People,dc=synrc,dc=com"
```

Delete
------

```
$ ldapmodify -f t/030-delete.ldif -h localhost -p 1389 -D "uid=admin,dc=synrc,dc=com" -w secret
> deleting entry "uid=alice,ou=People,dc=synrc,dc=com"
> deleting entry "cn=bob,ou=People,dc=synrc,dc=com"
$ ldapmodify -f t/031-delete-noobj.ldif -h localhost -p 1389 -D "uid=admin,dc=synrc,dc=com" -w secret
> deleting entry "cn=alice,ou=People,dc=synrc,dc=com"
> ldap_delete: No such object (32)
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

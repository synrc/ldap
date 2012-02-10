README
======
Erland Directory Server is an [LDAP](http://en.wikipedia.org/wiki/LDAP) server with [MongoDB](http://www.mongodb.org/) backend.

INSTALL
=======
Compile eMongo driver first:

        $ git clone git://github.com/master/emongo.git emongo
        $ cd emongo
        $ make
        $ cd ..

Download and compile EDS:

        $ git clone git://github.com/master/eds.git eds
        $ cd eds
        $ make

Populate database with sample LDIF:

        $ priv/populate.py t/000-init.ldif

        dc=synrc,dc=com
        uid=admin,dc=synrc,dc=com
        ou=People,dc=synrc,dc=com
        cn=Oleg Smirnov,ou=People,dc=synrc,dc=com
        cn=Maxim Sokhatsky,ou=People,dc=synrc,dc=com


USAGE
=====
        $ ./eds.sh

LDAP port is 1389 for testing purposes. Anonymous bind is not supported (yet).

Search
------
        $ ldapsearch -b "dc=synrc,dc=com" 'objectClass=*' \
                     -h localhost -p 1389 -D "uid=admin,dc=synrc,dc=com" -w secret

Filters:

        $ ldapsearch -b "dc=synrc,dc=com" '(&(uid=*)(cn=Ma*))' \
                     -h localhost -p 1389 -D "uid=admin,dc=synrc,dc=com" -w secret

Attributes selection:

        $ ldapsearch -b "dc=synrc,dc=com" 'sn=*' cn sn \
                     -h localhost -p 1389 -D "uid=admin,dc=synrc,dc=com" -w secret

Size limit on query result:

        $ ldapsearch -b "dc=synrc,dc=com" 'sn=*' cn sn -z 1 \
                     -h localhost -p 1389 -D "uid=admin,dc=synrc,dc=com" -w secret

Add
---

Adding entries:

        $ ldapmodify -f t/010-add.ldif \
                     -h localhost -p 1389 -D "uid=admin,dc=synrc,dc=com" -w secret	

        adding new entry "cn=alice,ou=People,dc=synrc,dc=com"

        adding new entry "cn=bob,ou=People,dc=synrc,dc=com"

Adding duplicate entries:

        $ ldapmodify -f t/011-add-exists.ldif \
                     -h localhost -p 1389 -D "uid=admin,dc=synrc,dc=com" -w secret

        adding new entry "cn=alice,ou=People,dc=synrc,dc=com"
        ldap_add: Already exists (68)


Modify
------

Replacing value of an attribute:

        $ ldapmodify -f t/020-modify-replace.ldif \
                     -h localhost -p 1389 -D "uid=admin,dc=synrc,dc=com" -w secret

        modifying entry "cn=alice,ou=People,dc=synrc,dc=com"

Adding new attribute:

        $ ldapmodify -f t/021-modify-add.ldif \
                     -h localhost -p 1389 -D "uid=admin,dc=synrc,dc=com" -w secret

        modifying entry "cn=alice,ou=People,dc=synrc,dc=com"

Deleting an attribute:

        $ ldapmodify -f t/022-modify-del.ldif \
                     -h localhost -p 1389 -D "uid=admin,dc=synrc,dc=com" -w secret

        modifying entry "cn=bob,ou=People,dc=synrc,dc=com"

Changing many attributes at once:

        $ ldapmodify -f t/023-modify-multi.ldif \
                     -h localhost -p 1389 -D "uid=admin,dc=synrc,dc=com" -w secret

        modifying entry "cn=bob,ou=People,dc=synrc,dc=com"

Changing nonexistent object:

        $ ldapmodify -f t/024-modify-noobj.ldif \
                     -h localhost -p 1389 -D "uid=admin,dc=synrc,dc=com" -w secret

        modifying entry "cn=eve,ou=People,dc=synrc,dc=com"
        ldap_modify: No such object (32)

Modify DN
---------
        $ ldapmodify -f t/025-modify-dn.ldif \
                     -h localhost -p 1389 -D "uid=admin,dc=synrc,dc=com" -w secret

        modifying rdn of entry "cn=alice,ou=People,dc=synrc,dc=com"

Delete
------
Deleting entries:

        $ ldapmodify -f t/030-delete.ldif \
                     -h localhost -p 1389 -D "uid=admin,dc=synrc,dc=com" -w secret

        deleting entry "uid=alice,ou=People,dc=synrc,dc=com"

        deleting entry "cn=bob,ou=People,dc=synrc,dc=com"

Deleting nonexistent entries:

        $ ldapmodify -f t/031-delete-noobj.ldif \
                     -h localhost -p 1389 -D "uid=admin,dc=synrc,dc=com" -w secret

        deleting entry "cn=alice,ou=People,dc=synrc,dc=com"
        ldap_delete: No such object (32)

Compare
-------
Evaluating an expression:

        $ ldapcompare "uid=admin,dc=synrc,dc=com" uid:admin \
                      -h localhost -p 1389 -D "uid=admin,dc=synrc,dc=com" -w secret
        TRUE

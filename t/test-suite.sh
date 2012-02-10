#!/bin/bash

ldap_search() {
    FILTER=${1:-'"objectClass=*"'}
    ARGS=$2' '$3' '$4$' '$5
    local CMD='ldapsearch -b "dc=synrc,dc=com" -h localhost -p 1389 -D "uid=admin,dc=synrc,dc=com" -w secret '$FILTER' '$ARGS
    eval $CMD
}

ldap_modify() {
    local CMD='ldapmodify -f '$1' -h localhost -p 1389 -D "uid=admin,dc=synrc,dc=com" -w secret 2>&1'
    eval $CMD
}

run_test() {
    echo -n " - "$1"... "
    RES=$($2)
    MOD=$(< $3)
    ( [ "$RES" = "$MOD" ] && echo "ok." ) || echo "Failed!"
}

run_test "Cleanup" "mongo --quiet eds t/000-cleanup.js" "t/000-cleanup.txt"

run_test "Initialization" "priv/populate.py t/000-init.ldif" "t/000-init.txt"

run_test "Search for 'objectClass=*'" "ldap_search" "t/000-search.txt"

run_test "Search for '(&(uid=*)(cn=Ma*))'" "ldap_search \"(&(uid=*)(cn=Ma*))\"" "t/001-search.txt"

run_test "Search with attribute selection" "ldap_search \"sn=*\" cn sn" "t/002-search.txt"

run_test "Search with size limit" "ldap_search \"sn=*\" cn sn -z1" "t/003-search.txt"

R=$(ldap_modify "t/010-add.ldif")
run_test "Adding entries" "ldap_search" "t/010-add.txt"

run_test "Adding duplicate entries" "ldap_modify \"t/011-add-exists.ldif\"" "t/011-add-exists.txt"

R=$(ldap_modify "t/020-modify-replace.ldif")
run_test "Replacing value of an attribute" "ldap_search" "t/020-modify-replace.txt"

R=$(ldap_modify "t/021-modify-add.ldif")
run_test "Adding new attribute" "ldap_search" "t/021-modify-add.txt"

R=$(ldap_modify "t/022-modify-del.ldif")
run_test "Deleting an attribute" "ldap_search" "t/022-modify-del.txt"

R=$(ldap_modify "t/023-modify-multi.ldif")
run_test "Changing many attributes at once" "ldap_search" "t/023-modify-multi.txt"

run_test "Changing nonexistent object" "ldap_modify \"t/024-modify-noobj.ldif\"" "t/024-modify-noobj.txt"

R=$(ldap_modify "t/025-modify-dn.ldif")
run_test "Modifying DN" "ldap_search" "t/025-modify-dn.txt"

R=$(ldap_modify "t/030-delete.ldif")
run_test "Deleting entries" "ldap_search" "t/030-delete.txt"

run_test "Deleting nonexistent entries" "ldap_modify \"t/031-delete-noobj.ldif\"" "t/031-delete-noobj.txt"

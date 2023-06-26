#!/bin/bash

sudo pkill slapd
sudo netstat -tnlp | grep "389\|636"
sudo slapd -h "ldap:/// ldapi:/// ldaps:///" -g openldap -u openldap -F /etc/ldap/slapd.d
sudo netstat -tnlp | grep "389\|636"

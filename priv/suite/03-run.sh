#!/bin/bash

# OpenLDAP restart

sudo pkill slapd
sudo /usr/sbin/slapd
# -h "ldap:/// ldapi:/// ldaps:///"
ps aux | grep slapd

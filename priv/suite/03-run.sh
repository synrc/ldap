#!/bin/bash

# OpenLDAP restart

sudo pkill slapd
sudo ./slapd -h "ldap:/// ldapi:/// ldaps:///"
ps aux | grep slapd

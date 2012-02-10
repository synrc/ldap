#!/usr/bin/python

import sys, pymongo

def ldif_parser(f):
    obj = dict()
    for line in f:
        line = line.strip()
        if len(line) == 0:
            yield obj
            obj = dict()
        else:
            [k, v] = line.split(': ')
            try:
                obj[k].append(v)
            except KeyError:
                obj[k] = v
            except AttributeError:
                obj[k] = [obj[k], v]
            if k == 'dn':
                rdn = list(v)
                rdn.reverse()
                obj['_rdn'] = ''.join(rdn)
                print v
    yield obj
    
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print "Usage: %s <ldif file>" % sys.argv[0]
    else:
        ldif = open(sys.argv[1], "r")
        conn = pymongo.connection.Connection()
        conn['eds']['root'].insert([item for item in ldif_parser(ldif)])
        conn['eds']['root'].ensure_index('_rdn')

#!/usr/bin/env python
import sys
import time
from getpass import getpass

import gpass

def escape(string):
    """
    From http://keepass.info/help/base/importexport.html
    """
    string = string.replace('&', '&amp;')
    string = string.replace('<', '&lt;')
    string = string.replace('>', '&gt;')
    string = string.replace('"', '&quot;')
    string = string.replace("'", '&apos;')
    return string

def write_entry(entry):
    """returns XML string for one password entry"""
    time_tup = time.gmtime(entry['updated'])
    updated = time.strftime('%FT%T', time_tup)
    lines = []
    lines.append('   <entry>')
    lines.append('    <title>' + escape(entry['name']) + '</title>')
    lines.append('    <username>' + escape(entry['username']) + '</username>')
    lines.append('    <password>' + escape(entry['password']) + '</password>')
    lines.append('    <url>' + escape(entry['hostname']) + '</url>')
    lines.append('    <comment>' + escape(entry['description']) + '</comment>')
    lines.append('    <icon>1</icon>')
    lines.append('    <creation>' + updated + '</creation>')
    lines.append('    <lastaccess>' + updated + '</lastaccess>')
    lines.append('    <lastmod>' + updated + '</lastmod>')
    #lines.append('    <expire></expire>')
    lines.append('   </entry>')
    return '\n'.join(lines)


if len(sys.argv) != 3:
    print ("Usage: %s input.gps output.xml" % (sys.argv[0]))
    sys.exit(1)

gp = gpass.GPass05()
with open(sys.argv[1], 'r') as f:
    data = f.read()

print("Note: this will write an *unencrypted* XML file of your passwords for")
print("importing them into KeePass. Please make sure the target file is")
print("accessible only by you (and preferably on an encrypted file system")
print("or tmpfs).\n")
pw = getpass('Please enter your GPass master password: ')
entries = gp.import_data(data, pw)

template = '''<!DOCTYPE KEEPASSX_DATABASE>
<database>
 <group>
  <title>GPass entries</title>
  <icon>1</icon>
  %s
 </group>
</database>'''
with open(sys.argv[2], 'w') as f:
    xml = ''
    for e in entries:
        xml += write_entry(e)
    f.write(template % xml)



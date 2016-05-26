#
# Revelation - a password manager for GNOME 2
# http://oss.codepoet.no/revelation/
# $Id: gpass.py 602 2007-01-03 08:06:28Z erikg $
#
# Module for handling GPass data
#
#
# Copyright (c) 2003-2006 Erik Grinaker
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

import base
#from revelation import data, entry

import locale, re
from Crypto.Cipher import Blowfish
from Crypto.Hash import SHA


IV	= "\x05\x17\x01\x7b\x0c\x03\x36\x5e"


def decrypt(ciphertext, password, magic = None):
	"Decrypts a data stream"

	# decrypt data
	if len(ciphertext) % 8 != 0:
		raise base.FormatError

	key		= SHA.new(password).digest()
	cipher		= Blowfish.new(key, Blowfish.MODE_CBC, IV)

	plaintext	= cipher.decrypt(ciphertext)

	# check magic string
	if magic != None:
		if plaintext[:len(magic)] != magic:	
			raise base.PasswordError

		else:
			plaintext = plaintext[len(magic):]

	# remove padding
	padchar = plaintext[-1]
	npadchar = ord(padchar)

	if (npadchar > 0):
		if plaintext[-npadchar:] != padchar * npadchar:
			raise base.FormatError

		plaintext = plaintext[:-npadchar]

	return plaintext


def encrypt(plaintext, password):
	"Encrypts a data stream"

	# right-pad data
	padlen = 8 - len(plaintext) % 8

	if padlen == 0:
		padlen = 8

	plaintext += chr(padlen) * padlen

	# encrypt data
	key	= SHA.new(password).digest()
	cipher	= Blowfish.new(key, Blowfish.MODE_CBC, IV)

	return cipher.encrypt(plaintext)




class GPass05(base.DataHandler):
	"Data handler for GPass 0.5.x data"

	name		= "GPass 0.5.x (or newer)"
	importer	= True
	exporter	= True
	encryption	= True


	def __init__(self):
		base.DataHandler.__init__(self)


	def __getint(self, input):
		"Fetches an integer from the input"

		if len(input) < 4:
			raise base.FormatError

		return ord(input[0]) << 0 | ord(input[1]) << 8 | ord(input[2]) << 16 | ord(input[3]) << 24


	def __getstr(self, input):
		"Fetches a string from the input"

		length = self.__getint(input[:4])

		if len(input) < (4 + length):
			raise base.FormatError

		string = input[4:4 + length]

		if len(string) != length:
			raise base.FormatError

		return string


	def __mkint(self, input):
		"Creates a string-representation of an integer"

		string = ""

		for i in range(4):
			string += chr(input >> i * 8 & 0xff)

		return string


	def __mkstr(self, input):
		"Makes a string suitable for inclusion in the data stream"

		return self.__mkint(len(input)) + input


	def __normstr(self, string):
		"Normalizes a string"

		string = re.sub("[\r\n]+", " ", string)
		string = string.decode(locale.getpreferredencoding(), "replace")
		string = string.encode("utf-8", "replace")

		return string


	def __packint(self, input):
		"Packs an integer"

		if input == 0:
			return "\x00"

		string = ""

		while input > 0:
			c	= input % 0x80
			input	= input / 0x80

			if input > 0:
				c |= 0x80

			string += chr(c)

		return string


	def __packstr(self, input):
		"Packs a string"

		return self.__packint(len(input)) + input


	def __unpackint(self, input):
		"Fetches a packed number from the input"

		value	= 0
		b	= 1

		for i in range(min(len(input), 6)):
			c = ord(input[i])

			if c & 0x80:
				value	+= b * (c & 0x7f)
				b	*= 0x80;

			else:
				value	+= b * c

				return i + 1, value

		# if we didn't return in the for-loop, the input is invalid
		else:
			raise base.FormatError


	def __unpackstr(self, input):
		"Unpacks a string from the input"

		cut, length = self.__unpackint(input[:6])

		if len(input) < cut + length:
			raise base.FormatError

		return cut + length, input[cut:cut + length]


	def import_data(self, input, password):
		"Imports data from a data stream to an entrystore"

		plaintext = decrypt(input, password, "GPassFile version 1.1.0")

		entries = []

		while len(plaintext) > 0:

			# parse data
			id		= self.__getint(plaintext[:4])
			plaintext	= plaintext[4:]

			parentid	= self.__getint(plaintext[:4])
			plaintext	= plaintext[4:]

			entrytype	= self.__getstr(plaintext)
			plaintext	= plaintext[4 + len(entrytype):]

			attrdata	= self.__getstr(plaintext)
			plaintext	= plaintext[4 + len(attrdata):]


			l, name		= self.__unpackstr(attrdata)
			attrdata	= attrdata[l:]

			l, desc		= self.__unpackstr(attrdata)
			attrdata	= attrdata[l:]

			l, ctime	= self.__unpackint(attrdata)
			attrdata	= attrdata[l:]

			l, mtime	= self.__unpackint(attrdata)
			attrdata	= attrdata[l:]

			l, expire	= self.__unpackint(attrdata)
			attrdata	= attrdata[l:]

			l, etime	= self.__unpackint(attrdata)
			attrdata	= attrdata[l:]

			if entrytype == "general":
				l, username	= self.__unpackstr(attrdata)
				attrdata	= attrdata[l:]

				l, password	= self.__unpackstr(attrdata)
				attrdata	= attrdata[l:]

				l, hostname	= self.__unpackstr(attrdata)
				attrdata	= attrdata[l:]

			else:
				username = password = hostname = ""


			# create entry
			if entrytype == "general":
				e = dict()
				e['name']			= self.__normstr(name)
				e['description']		= self.__normstr(desc)
				e['updated']		= mtime

				e['hostname']	= self.__normstr(hostname)
				e['username']	= self.__normstr(username)
				e['password']	= self.__normstr(password)
				entries.append(e)

			#elif entrytype == "folder":
			#	e = entry.FolderEntry()

			#	e.name			= self.__normstr(name)
			#	e.description		= self.__normstr(desc)
			#	e.updated		= mtime

			else:
				continue


		return entries


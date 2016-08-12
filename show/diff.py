import optparse
import sys
import os
import difflib
import time
import re

"""
Generates an HTML Diff of two textfiles
"""

def diff(fromfile, tofile, writefile):

	fromdate = time.ctime(os.stat(fromfile).st_mtime)
	todate = time.ctime(os.stat(tofile).st_mtime)
	fromlines = open(fromfile, 'U').readlines()
	tolines = open(tofile, 'U').readlines()
	diff = difflib.HtmlDiff().make_file(fromlines, tolines, fromfile, tofile)


	with open(writefile, 'w+') as wfile:
		wfile.writelines(diff)

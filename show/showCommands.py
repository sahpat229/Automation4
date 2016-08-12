import paramiko
import re
import getpass
import time
import csv
import sys
import os
import difflib
import subprocess

'''
Checks if the host_ip is in the proper format
'''

def hostProperFormat(host_ip):
	splitted = re.split('\.', host_ip)

	if not len(splitted) == 4:
		return False

	else:
		for field in splitted:
			if not (0 <= int(field)) and (int(field) <= 255):
				return False
			else:
				continue
		return True

'''
validates host_ip 
'''
def validateHost(host_ip):
	while(not hostProperFormat(host_ip)):
		host_ip = raw_input("HOST IP: ")
	return host_ip

'''
gets a list containing a username and password
'''
def get_user_pass():
	username = raw_input("Username: ")
	password = getpass.getpass()
	return [username, password]

'''
custom exception class to capture string values
'''
class IPException(Exception):
	def __init__(self, value):
		self.value = value
	def __str__(self):
		return self.value

'''
return a channel after connecting to the host designated by host_ip
'''
def startConnection(host_ip, us, passw):
	# validip = validateHost(host_ip)
	"""
	Starts a client, sets is host key policy and loads the current system host keys

	paramiko exceptions are converte to custom IPException class for easier handling 
	outside
	"""
	client = paramiko.SSHClient()
	client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	client.load_system_host_keys()
	try:
		client.connect(hostname=host_ip, username=us, password=passw)
	except paramiko.BadHostKeyException:
		raise IPException("Server's host key could not be verified.")
	except paramiko.AuthenticationException:
		raise IPException("Authentication Error")
	except paramiko.SSHException: 
		raise IPException("Could not connect to Host via SSH")
	except Exception:
		raise IPException("Could not connect to Host via SSH")
	try:
		channel = client.invoke_shell()
	except Exception:
		raise IPException("Error occured in starting shell")
	else:
		time.sleep(0.1)
		channel.keep_this = client
		return channel

"""
Takes a channel and inputs a command denoted by com into the channel
Extracts the outputs of the command
"""

def input_receive_comm(channel, com, hostname):
	output = ""

	while True:
		if channel.send_ready():
			break
		else: 
			pass
	channel.send(com)

	while True:
		if channel.recv_ready():
			break
		else:
			pass
			#print "in loop 2"

	# counter = 0

	# while True:
	# 	if (not channel.recv_ready()) and (counter < 40):
	# 		#print "in sec 3, counter = ", counter
	# 		time.sleep(0.05)
	# 		counter += 1
	# 	elif (not channel.recv_ready()) and (counter == 40):
	# 		#print "in sec 4, counter = ", counter
	# 		counter = 0
	# 		break
	# 	elif channel.recv_ready():
	# 		#print "in sec 5, counter = ", counter
	# 		output += channel.recv(10000)
	# 		counter = 0
	# while channel.recv_ready():
	# 	output += channel.recv(5000)
	# 	print output


	# '''
	# Search for hostname# within output, break, and return collected output
	# '''
	while True:
		if not channel.recv_ready():
			pass
		if channel.recv_ready():
			local_output = channel.recv(50000)
			if re.search(hostname+"#", local_output) == None:
				output += local_output
			else:
				output += local_output
				break

	
	return output


# def main():
# 	usage = "usage: %prog [options] hostname configfile tofile"
# 	parser = optparse.OptionParser(usage)
# 	parser.add_option("-p", action="store",	help="Password input")
# 	parser.add_option("-u", action="store", help="Username input")
# 	(options, args) = parser.parse_args(args)
# 	password = options.p
# 	username = options.u
# 	configfile = args[1]
# 	hostname = args[0]
# 	tofile = args[2]
# 	if hostProperFormat(hostname):
# 		try:
# 			channel = startConnection(hostname, username, password)
# 		except 


"""
Collect the outputs for all commands executed on each host in individual outiflenames designated
by outfilenames
"""
def execute(hosts, username, password, commands, outfilenames, tags_remarks):
	tuples = zip(hosts, outfilenames)
	for host_outfile in tuples:
		#print host_outfile[0], username, password
		channel = startConnection(host_outfile[0], username, password)
		while True:			
			if channel.recv_ready():
				local_output = channel.recv(500000)
				if re.search(host_outfile[0]+'#', local_output) != None:
					break
		while True:
			if channel.send_ready():
				break
			else: 
				pass
		channel.send("term length 0\n")
		# time.sleep(0.2)
		# channel.recv(50000)
		# channel.send("en\n")
		# time.sleep(0.2)
		# channel.recv(50000)
		# channel.send(password+"\n")
		while True:
			if channel.recv_ready():
				local_output = channel.recv(500000)			
				if re.search(host_outfile[0]+'#', local_output) != None:
					break
		# output = input_receive_comm(channel, "en\n")
		# output = input_receive_comm(channel, password + "\n")

		while True:
			if channel.send_ready():
				break
			else:
				pass

		with open(host_outfile[1], 'w+') as outputfile:
			for command in commands:
				output_line = input_receive_comm(channel, 
					(command+"\n"), host_outfile[0]) + "\n"
				outputfile.write(output_line)
			outputfile.write(tags_remarks)	
			
		channel.close()	
	# else:
	# 	raise IPException("Host not proper format")

# """
# Just like execute but instead returns the output instead of writing it to a file
# """
def execute_str(host, username, password, command):
	channel = startConnection(host, username, password)
	while True:			
		if channel.recv_ready():
			local_output = channel.recv(500000)
			if re.search(host+'#', local_output) != None:
				break
	while True:
		if channel.send_ready():
			break
		else: 
			pass
	channel.send("term length 0\n")
	# time.sleep(0.2)
	# channel.recv(50000)
	# channel.send("en\n")
	# time.sleep(0.2)
	# channel.recv(50000)
	# channel.send(password+"\n")
	while True:
		if channel.recv_ready():
			local_output = channel.recv(500000)			
			if re.search(host+'#', local_output) != None:
				break
	# output = input_receive_comm(channel, "en\n")
	# output = input_receive_comm(channel, password + "\n")

	while True:
		if channel.send_ready():
			break
		else:
			pass
	# output = input_receive_comm(channel, "en\n")
	# output = input_receive_comm(channel, password + "\n")
	output_line = input_receive_comm(channel, 
			(command+"\n"), host) + "\n"

	return output_line
	
# """
# deprecated
# """

def runCommands(hostname, username, password, commands, outfilename, tags_remarks):
	ssh = paramiko.SSHClient()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	ssh.connect(hostname,username=username,password=password)
	ssh_transport = ssh.get_transport()
	list_outputs = []
	for command in commands:
	    chan = ssh_transport.open_session()
	    chan.exec_command(command+"\n")
	    exit_code = chan.recv_exit_status()
	    stdin = chan.makefile('wb', -1)         # pylint: disable-msg=W0612
	    stdout = chan.makefile('rb', -1)
	    stderr = chan.makefile_stderr('rb', -1)  # pylint: disable-msg=W0612
	    output = stdout.read()
	    list_outputs.append(hostname + ": " + command + "\n" + output)
	with open(outfilename, 'w+') as outfile:
		for output in list_outputs:
			outfile.write(output)
		outfile.write(tags_remarks)
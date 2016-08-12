import paramiko
import socket


class IPException(Exception):
	def __init__(self, value):
		self.value = value
	def __str__(self):
		return self.value


def createConnectedTransport(address, port, username, password):
	transport = paramiko.transport.Transport(socket.create_connection((address, port)))
	try:
		transport.start_client()
	except paramiko.SSHException:
		raise IPException("Negotiation failed")
	else:
		try:
			transport.auth_password(username, password)
		except paramiko.BadAuthenticationType:
			raise IPException("Password authentication is not allowed for this user")
		except paramiko.AuthenticationException:
			raise IPException("Authentication failed")
		except paramiko.SSHException:
			raise IPException("There was a network error")
		else:
			return transport

def input_receive_comm(channel, com):
	while not channel.send_ready():
		pass
	channel.send(com)
	output = ""
	while not channel.send_ready()
		output += channel.recv(5000)
	return output



def runCommands(address, username, password, commands, outfilename, tags_remarks):
	transport = createConnectedTransport(address, 22, username, password)
	list_outputs = []
	for command in commands:
		try:
			channel = transport.open_session()
		except paramiko.SSHException:
			raise IPException("Request rejected or session ended prematurely")
		else:
			try:
				channel.exec_command(command + "\n")
				output = channel.recv(5000)
			except paramiko.SSHException:
				raise IPException("Request was rejected or the channel was closed during command execution")
			else:
				list_outputs.append(output)
	with open(outfilename, 'w+') as outfile:
		for output in list_outputs:
			outfile.write(output)
		outfile.write(tags_remarks)

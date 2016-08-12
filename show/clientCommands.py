import paramiko

class IPException(Exception):
	def __init__(self, value):
		self.value = value
	def __str__(self):
		return self.value

def runCommands(hostname, username, password, commands, outfilename, tags_remarks):
	client = paramiko.SSHClient()
	client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	client.load_system_host_keys()
	client.connect(hostname=hostname, username=username, password=password)
	list_outputs = []
	for command in commands:
		stdout = client.exec_command(command+"\n")[1]
		list_outputs.append(hostname + ": " + command+ "\n" + stdout.read())
	with open(outfilename, 'w+') as outfile:
		for output in list_outputs:
			outfile.write(output)
		outfile.write(tags_remarks)

# runCommands(hostname="cisco1", username="cisco", password="cisco",
# 	commands=["show ip int b"], outfilename="output.txt", tags_remarks="hello")
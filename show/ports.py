import paramiko
import showCommands
import datetime
import re
from show.models import PortModel

def generate_report(host_list, username, password):
	for host in host_list:
		NXOS = False
		if re.search('Cisco Nexus Operating System',
			showCommands.execute_str(host, username, password, 'show version')) != None:
			NXOS = True

		output = showCommands.execute_str(host, username, password, 'show interface status')
		#print output
		if NXOS:
			real_output = re.split('\n', output)
			real_output = real_output[5:len(real_output) - 2]
		else:
			real_output = re.split('\n', output)
			real_output = real_output[6:len(real_output) - 2] 

		date = str(datetime.datetime.now())
		date = re.split(' ', date)[0]
		total = len(real_output)

		output = showCommands.execute_str(host, username, password, 'show interface status | include connected')
		if NXOS:
			real_output = re.split('\n', output)
			real_output = real_output[5:len(real_output) - 2]
		else:
			real_output = re.split('\n', output)
			real_output = real_output[6:len(real_output) - 2]

		connected = len(real_output)

		try:
			instance = PortModel.objects.get(hostname=host, date=date)
		except Exception:
			pass
		else:
			instance.delete()
			
		portModel = PortModel(hostname=host, date=date, connected=connected, notconnected=(total-connected))
		portModel.save()

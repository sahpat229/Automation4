#!/usr/bin/python

"""
Same as subnet.py but is an executable
"""


import showCommands
import datetime
import re
import threading
import time
import os
import argparse
from crontab import CronTab

def convertMask(mask):
	if re.search('\.', mask) == None:
		print True
		number_of_ones = int(mask)
		groups = number_of_ones / 8
		new_mask = ""
		for x in range(groups):
			new_mask+="255."
		remainder = number_of_ones % 8
		number_of_zeros = 8 - remainder
		mask_appendage = 0
		for x in range(remainder):
			mask_appendage += 2**number_of_zeros
			number_of_zeros += 1
		if groups < 3:
			mask_appendage = str(mask_appendage)
			mask_appendage += "."
			new_mask += mask_appendage
			for x in range(3 - groups):
				if x == (2 - groups):
					new_mask += "0"
				else:
					new_mask += "0."
		else:
			new_mask += str(mask_appendage)

		return new_mask

	else:
		return mask

mapper = {'0' : 0, '128' : 1, '192' : 2, '224' : 3, '240' : 4, '248' : 5, '252' : 6, '254' : 7, '255' : 8}
def getNetworkID(ipaddress, mask):
	fields = re.split('\.', ipaddress)
	fields = map(int, fields)
	mask_fields = re.split('\.', mask)
	mask_fields = map(int, mask_fields)
	ip_id = ""
	for index in range(len(fields)):
		field = fields[index]
		mask = mask_fields[index]
		result = bin(field & mask)
		result = int(result, 2)
		if index == (len(fields) - 1):
			ip_id += str(result)
		else:
			ip_id += str(result) + "."

	return ip_id

def testIP(field, mask):
	result = bin(field & mask)
	return int(result, 2)
	binary_field = ""
	counter = 0
	while (field > 0):
		counter += 1
		number = field % 2
		field /= 2
		binary_field = str(number) + binary_field
	while (counter < 8):
		binary_field = '0' + binary_field
		counter += 1

	return binary_field

class showThread(threading.Thread):
	def __init__(self, host, username, password, outfile_date):
		threading.Thread.__init__(self)
		self.host = host
		self.username = username
		self.password = password
		self.outfile_date = outfile_date
	def run(self):
		PATH_subnet_outputs = '/etc/ansible/showsite/show/subnet_outputs/'
		host = self.host
		username = self.username
		password = self.password
		outfile_date = self.outfile_date
		NXOS = False
		if re.search('Cisco Nexus Operating System',
			showCommands.execute_str(host, username, password, 'show version')) != None:
			NXOS = True
		# thread.start_new_thread(showCommands.execute, ([host], username, password, ['term length 0', 'show ip int b | include up'],
		# 	[host+outfile_date+".txt"], ''))
		# thread.exit()
		print PATH_subnet_outputs+host+"_"+outfile_date+".txt"
		showCommands.execute([host], username, password, ['term length 0', 'show ip int b | include up'],
			[PATH_subnet_outputs + host+"_"+outfile_date+".txt"], '')

		with open(PATH_subnet_outputs + host+"_"+outfile_date+".txt", 'r') as file:
			file_all = file.read()
			first_split = re.split('include up[\r\n]*', file_all)[1]
			second_split = re.split('[ \r\n]*' + host+"#" + '[ \r\n]*', first_split)[0]
			third_split = re.split('[ \r\n]*', second_split)
			print third_split
			list_interface_names = []
			list_interface_addresses = []
			if NXOS:
				for i in range(len(third_split)):
					if (i % 3) == 0:
						list_interface_names.append(third_split[i].strip())
					if (i % 3) == 1:
						list_interface_addresses.append(third_split[i].strip())
			else:
				for i in range(len(third_split)):
					if (i % 6) == 0:
						list_interface_names.append(third_split[i].strip())
					if (i % 6) == 1:
						list_interface_addresses.append(third_split[i].strip())

			list_commands = ["show running-config interface " + name for name in list_interface_names]

		showCommands.execute([host], username, password, ['term length 0'] + list_commands, [PATH_subnet_outputs + host+"_"+
			"detail_" + outfile_date + ".txt"], '')

		list_descriptions = []
		list_masks = []

		with open(PATH_subnet_outputs + host+"_detail_" + outfile_date +".txt", 'r') as file:
			description_found = False
			for line in file:				
				if re.search('description', line) != None:
					list_descriptions.append((re.split(' *description *', line)[1]).strip())
					description_found = True
				if re.search('ip address', line) != None:
					list_masks.append(convertMask((re.split(' *ip address *[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3} */*', line)[1])).strip())
					if not description_found:
						list_descriptions.append("")
				if re.search(host+"#", line) != None:
					description_found = False
		network_ids = map(getNetworkID, list_interface_addresses, list_masks)
		all_fields = zip(list_interface_names, list_interface_addresses, list_masks, network_ids, list_descriptions)
		with open(PATH_subnet_outputs + host+"_detail_" + outfile_date + ".json", 'w+') as file:
			file.write('{"' + host + '": [')
			for index in range(len(all_fields)):
				field_tuple = all_fields[index]
				interface_address = field_tuple[1].strip()
				interface_mask = field_tuple[2].strip()

				if index != (len(all_fields) - 1):
					file.write('{"interface_name" : ' + '"' + field_tuple[0] + '"' + ',')
					file.write('"interface_address" : ' + '"' +field_tuple[1] + '"' + ',')
					file.write('"interface_mask" : ' + '"' + field_tuple[2] + '"' + ',')
					file.write('"network_id" : ' + '"' + field_tuple[3]
						+ '"' + ',')
					file.write('"interface_description" : ' + '"' + field_tuple[4] + '"' + '},')
				else:
					file.write('{"interface_name" : ' + '"' + field_tuple[0] + '"' + ',')
					file.write('"interface_address" : ' + '"' +field_tuple[1] + '"' + ',')
					file.write('"interface_mask" : ' + '"' + field_tuple[2] + '"' + ',')
					file.write('"network_id" : ' + '"' + field_tuple[3]
						+ '"' + ',')
					file.write('"interface_description" : ' + '"' + field_tuple[4] + '"' + '}')
			file.write(']}')

		with open(PATH_subnet_outputs + host + "_report_" + outfile_date + ".txt", 'w+') as file:
			initial_line = '{:<15s} {:>20s} {:>20s} {:>20s} {:>40s}'.format('Name', 'Address', 'Mask', 'ID',
					'Description')
			file.write(initial_line + "\n")
			for field_tuple in all_fields:
				line = '{:<15s} {:>20s} {:>20s} {:>20s} {:>40s}'.format(field_tuple[0], field_tuple[1], 
					field_tuple[2], field_tuple[3], field_tuple[4])
				file.write(line + "\n")

		for fields_tuple in all_fields:
			#print fields_tuple
			try:
				NetworkID_object = NetworkID.objects.get(interface_name=fields_tuple[0], network_ID=fields_tuple[3],
					hostname=host, mask=fields_tuple[2])
			except ObjectDoesNotExist:
				NetworkID_object = NetworkID(interface_name=fields_tuple[0], network_ID=fields_tuple[3],
					hostname=host, mask=fields_tuple[2])
				NetworkID_object.save()
			else:
				NetworkID_object.delete()
				NetworkID_object = NetworkID(interface_name=fields_tuple[0], network_ID=fields_tuple[3],
					hostname=host, mask=fields_tuple[2])
				NetworkID_object.save()

		return


def execute(host_list, username, password):
	#print "IN execute"
	PATH_subnet_outputs = '/etc/ansible/showsite/show/subnet_outputs/'
	outfile_date = ""
	for item in re.split(' ', str(datetime.datetime.now())):
		outfile_date += item + "_"

	threads = []
	for host in host_list:
		newThread = showThread(host, username, password, outfile_date)
		newThread.start()
		threads.append(newThread)

	for t in threads:
		t.join()

# """
# Added option parsing for executable usage
# """

def main():
	"""
	Added --hosts, --username, and --password as options
	--hosts takes a list of hosts, separated by spaces, i.e. "cisco1 cisco2 cisco3 cisco4"
	--username only takes one username
	--password only takes one password
	"""
	parser = argparse.ArgumentParser(description = "")
	parser.add_argument('--hosts', nargs='+')
	parser.add_argument('--username', nargs='?')
	parser.add_argument('--password', nargs='?')
	args = vars(parser.parse_args())
	execute(args['hosts'], args['username'], args['password'])

def read_outputs():
	PATH_subnet_outputs = '/etc/ansible/showsite/show/subnet_outputs/'
	hosts_info = []
	host_names = []
	list_items = os.listdir(PATH_subnet_outputs)
	list_items.sort()
	this_object = {'host_name' : '', 'dates_list': []}
	counter = 0
	for item in list_items:
			if re.search('.json', item) != None:
				[host_name, date] = re.split('(?:_detail_)*(?:_.json)*', item)[0:2]
				if not host_name in host_names:
					if counter == 0:
						host_names.append(host_name)
						this_object = {'host_name' : '', 'dates_list': []}
						this_object['host_name'] = host_name
						this_object['dates_list'].append(date)
						counter = 1
					else:
						hosts_info.append(this_object)						
						host_names.append(host_name)
						this_object = {'host_name' : '', 'dates_list': []}
						this_object['host_name'] = host_name
						this_object['dates_list'].append(date)
				else:
					this_object['dates_list'].append(date)
	hosts_info.append(this_object)
	print hosts_info

def isWithinRange(ip_address, netwk_id, netwk_mask):
	object_ip = netwk_id
	object_mask = netwk_mask
	mask_fields = re.split('\.', object_mask)
	total_ones = 0
	for mask_field in mask_fields:
		total_ones += mapper[mask_field]

	object_ip_fields = re.split('\.', object_ip)
	object_ip_fields = map(int, object_ip_fields)
	ip_address_fields = re.split('\.', ip_address)
	ip_address_fields = map(int, ip_address_fields)

	object_string = ""
	ip_string = ""
	for index in range(len(object_ip_fields)):
		object_field = object_ip_fields[index]
		ip_field = ip_address_fields[index]
		object_string += format(object_field, '008b')
		ip_string += format(ip_field, '008b')

	for i in range(total_ones):
		if (object_string[i] != ip_string[i]):
			return False

	return True

# """
# Used to execute main when run as an executable
# """

if __name__ == "__main__":
	main()
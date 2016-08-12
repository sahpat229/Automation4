import showCommands
import datetime
import re
import threading
import time
import os
from models import NetworkID
from django.core.exceptions import ObjectDoesNotExist

"""
BASE SUBNET OUTPUT GENERATOR SCRIPT

subnet_exec.py is basically a copy of this but changed into executable format
"""




"""
converts a mask given as \24 to dotted format

FOR OPTIMAL PERFORMANCE, JUST HARDCODE A DICTIONARY translating
slash format subnet masks to dotted format subnet masks
"""

def convertMask(mask):

	"""IF there is no dot in the mask then execute this function"""
	if re.search('\.', mask) == None:
		# """Convert the string mask into an int and that is the number of leading ones in the binary
		# version of the mask
		# """
		number_of_ones = int(mask)
		groups = number_of_ones / 8 
		# """ Number of "groups" that are filled with 1's, in 255.255.255.0, each 255 is a group"""
		new_mask = ""
		# """
		# For each group thats filled with all one's append 255. to the new string 
		# """
		for x in range(groups):
			new_mask+="255."
		remainder = number_of_ones % 8
		# """
		# Calculate the number of zeros to be used to generate the mask appendage
		# """
		number_of_zeros = 8 - remainder
		mask_appendage = 0
		for x in range(remainder):
			mask_appendage += 2**number_of_zeros #set mask_appendage to 2**number_of_zeros since that correspondes to the string form of number_of_zeros
			number_of_zeros += 1
		if groups < 3:
			mask_appendage = str(mask_appendage)
			mask_appendage += "."
			new_mask += mask_appendage

			#add extraneous 0s if required, i.e., if only 255.0. was added in the previous part, add the last two 0's
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

# """
# change an IP address to its corresponding network ID form given the mask
# """
def getNetworkID(ipaddress, mask):
	"""
	Get each of the fields and convert them from str to int of ipaddress and mask
	"""
	fields = re.split('\.', ipaddress)
	fields = map(int, fields)
	mask_fields = re.split('\.', mask)
	mask_fields = map(int, mask_fields)
	ip_id = ""
	for index in range(len(fields)):
		field = fields[index]
		mask = mask_fields[index]
		# """
		# binary AND the fields from ipaddress and mask, and add the str(int()) version of that to the ip_id
		# """
		result = bin(field & mask)
		result = int(result, 2)
		if index == (len(fields) - 1):
			ip_id += str(result)
		else:
			ip_id += str(result) + "."

	return ip_id

# """
# Test function
# """

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

# """
# Threaded version to execute script on multiple hosts
# """

class showThread(threading.Thread):
	def __init__(self, host, username, password, outfile_date):
		threading.Thread.__init__(self)
		self.host = host
		self.username = username
		self.password = password
		self.outfile_date = outfile_date

	# """
	# run function details the execution of threads
	# """
	def run(self):
		"""
		PATH_subnet_outputs details the path in which to put the outputfiles
		"""
		PATH_subnet_outputs = os.getcwd() + '/show/subnet_outputs/'
		#print PATH_subnet_outputs
		host = self.host
		username = self.username
		password = self.password
		outfile_date = self.outfile_date
		# """
		# Searches through show version command for Cisco Nexus Operating System to determine if the device is IOS
		# or NXOS
		# """
		NXOS = False
		nxus = showCommands.execute_str(host, username, password, 'show version')
		
		if re.search('Cisco Nexus Operating System',
			showCommands.execute_str(host, username, password, 'show version')) != None:
			NXOS = True
		# thread.start_new_thread(showCommands.execute, ([host], username, password, ['term length 0', 'show ip int b | include up'],
		# 	[host+outfile_date+".txt"], ''))
		# thread.exit()
		#print PATH_subnet_outputs+host+"_"+outfile_date+".txt"
		# """
		# Executes term length 0 and show ip int b| include up on the host demarcated by self.host
		# and stores the output into a text file in the PATH_subnet_outputs
		# """

		#print "BEFORE: "

		showCommands.execute([host], username, password, ['term length 0', 'show ip int b | include up'],
			[PATH_subnet_outputs + host+"_"+outfile_date+".txt"], '')

		#print "AFTER: "

		# """
		# Reads the output that was just stored, and parses it for interface names and addresses
		# Stores the interface names and addresses in list_interface_names and list_interface_addresses, respectively
		# """

		with open(PATH_subnet_outputs + host+"_"+outfile_date+".txt", 'r') as file:
			file_all = file.read()
			first_split = re.split('include up[\r\n]*', file_all)[1]
			second_split = re.split('[ \r\n]*' + host+"#" + '[ \r\n]*', first_split)[0]
			third_split = re.split('[ \r\n]*', second_split)
			#print third_split
			list_interface_names = []
			list_interface_addresses = []
			if NXOS:
				for i in range(len(third_split)):
					if (i % 3) == 0:
						list_interface_names.append(third_split[i].strip())
					if (i % 3) == 1:
						if not third_split[i].strip() == "unassigned":
							list_interface_addresses.append(third_split[i].strip())
			else:
				for i in range(len(third_split)):
					if (i % 6) == 0:
						list_interface_names.append(third_split[i].strip())
					if (i % 6) == 1:
						if not third_split[i].strip() == "unassigned":
							list_interface_addresses.append(third_split[i].strip())

			list_commands = ["show running-config interface " + name for name in list_interface_names]

		# """
		# Executes term length 0 and show running-config interface on all the interfaces in list_interface_names
		# Stores the output in a textfile with hostname and _detail_ in the filename
		# """
		showCommands.execute([host], username, password, ['term length 0'] + list_commands, [PATH_subnet_outputs + host+"_"+
			"detail_" + outfile_date + ".txt"], '')

		list_descriptions = []
		list_masks = []

		# """
		# Opens the stored _detail_ file and parses the output for a description and mask.
		# Stores the mask and description into list_masks and list_descriptions, respectively
		# """

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



		#print "LIST_INTERFACE_ADDRESSES: ", list_interface_addresses
		#print "LIST_MASKS: ", list_masks
		# """
		# network_ids is the result of calling getNetworkID on all the interface addresses and masks in list_interface_address and
		# list_masks.  all_fields zips up all 5 lists made, into tuples with 5 elements
		# """

		network_ids = map(getNetworkID, list_interface_addresses, list_masks)
		all_fields = zip(list_interface_names, list_interface_addresses, list_masks, network_ids, list_descriptions)

		# """
		# Creates a JSON file that contains the data from list_interface_names, list_interface_addresses, list_masks,
		# network_ids, and list_descriptions.  JSON is used so that Django can return a JsonResponse to the HTML page
		# so the HTML page can generate appropriate tables and information
		# """
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

		# """
		# Creates a tabularly formatted textfile with all the information from the lists that were used to
		# create the JSON file.  This textfile is generated for the htmldiff module to perform diffs between
		# dates.  
		# """

		with open(PATH_subnet_outputs + host + "_report_" + outfile_date + ".txt", 'w+') as file:
			initial_line = '{:<15s} {:>20s} {:>20s} {:>20s} {:>40s}'.format('Name', 'Address', 'Mask', 'ID',
					'Description')
			file.write(initial_line + "\n")
			for field_tuple in all_fields:
				line = '{:<15s} {:>20s} {:>20s} {:>20s} {:>40s}'.format(field_tuple[0], field_tuple[1], 
					field_tuple[2], field_tuple[3], field_tuple[4])
				file.write(line + "\n")


		# """
		# Stores the information demarcated in the JSON files into multiple NetworkID_objects.  This is for later retrieval
		# for the search mechanism that tries to match a search input to its subnet ID and appropriate information.
		# """
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


# """
# Execute is the main function that creates each of the threads and executes them
# """

def execute(host_list, username, password):
	#print "IN execute"
	PATH_subnet_outputs = '/etc/ansible/showsite/show/subnet_outputs/'

	# """
	# creates a string representing the current time
	# """
	outfile_date = ""
	for item in re.split(' ', str(datetime.datetime.now())):
		outfile_date += item + "_"

	threads = []
	# """
	# creates the threads
	# """
	for host in host_list:
		newThread = showThread(host, username, password, outfile_date)
		newThread.start()
		threads.append(newThread)

	# """
	# executes the threads and ends hanging processing
	# """
	for t in threads:
		t.join()

	#print (time.time() - start_time)
	# for host in host_list:
	# 	NXOS = False
	# 	if re.search('Cisco Nexus Operating System',
	# 		showCommands.execute_str(host, username, password, 'show version')) != None:
	# 		NXOS = True
	# 	# thread.start_new_thread(showCommands.execute, ([host], username, password, ['term length 0', 'show ip int b | include up'],
	# 	# 	[host+outfile_date+".txt"], ''))
	# 	# thread.exit()
	# 	print PATH_subnet_outputs+host+"_"+outfile_date+".txt"
	# 	showCommands.execute([host], username, password, ['term length 0', 'show ip int b | include up'],
	# 		[PATH_subnet_outputs + host+"_"+outfile_date+".txt"], '')

	# 	with open(PATH_subnet_outputs + host+"_"+outfile_date+".txt", 'r') as file:
	# 		file_all = file.read()
	# 		first_split = re.split('include up[\r\n]*', file_all)[1]
	# 		second_split = re.split('[ \r\n]*' + host+"#" + '[ \r\n]*', first_split)[0]
	# 		third_split = re.split('[ \r\n]*', second_split)
	# 		print third_split
	# 		list_interface_names = []
	# 		list_interface_addresses = []
	# 		if NXOS:
	# 			for i in range(len(third_split)):
	# 				if (i % 3) == 0:
	# 					list_interface_names.append(third_split[i].strip())
	# 				if (i % 3) == 1:
	# 					list_interface_addresses.append(third_split[i].strip())
	# 		else:
	# 			for i in range(len(third_split)):
	# 				if (i % 6) == 0:
	# 					list_interface_names.append(third_split[i].strip())
	# 				if (i % 6) == 1:
	# 					list_interface_addresses.append(third_split[i].strip())

	# 		list_commands = ["show running-config interface " + name for name in list_interface_names]

	# 	showCommands.execute([host], username, password, ['term length 0'] + list_commands, [PATH_subnet_outputs + host+"_"+
	# 		"detail_" + outfile_date + ".txt"], '')

	# 	list_descriptions = []
	# 	list_masks = []

	# 	with open(PATH_subnet_outputs + host+"_detail_" + outfile_date +".txt", 'r') as file:
	# 		description_found = False
	# 		for line in file:				
	# 			if re.search('description', line) != None:
	# 				list_descriptions.append((re.split(' *description *', line)[1]).strip())
	# 				description_found = True
	# 			if re.search('ip address', line) != None:
	# 				list_masks.append(convertMask((re.split(' *ip address *[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3} */*', line)[1])).strip())
	# 				if not description_found:
	# 					list_descriptions.append("")
	# 			if re.search(host+"#", line) != None:
	# 				description_found = False
	# 	network_ids = map(getNetworkID, list_interface_addresses, list_masks)
	# 	all_fields = zip(list_interface_names, list_interface_addresses, list_masks, network_ids, list_descriptions)
	# 	with open(PATH_subnet_outputs + host+"_detail_" + outfile_date + ".json", 'w+') as file:
	# 		file.write('{"' + host + '": [')
	# 		for index in range(len(all_fields)):
	# 			field_tuple = all_fields[index]
	# 			interface_address = field_tuple[1].strip()
	# 			interface_mask = field_tuple[2].strip()

	# 			if index != (len(all_fields) - 1):
	# 				file.write('{"interface_name" : ' + '"' + field_tuple[0] + '"' + ',')
	# 				file.write('"interface_address" : ' + '"' +field_tuple[1] + '"' + ',')
	# 				file.write('"interface_mask" : ' + '"' + field_tuple[2] + '"' + ',')
	# 				file.write('"network_id" : ' + '"' + field_tuple[3]
	# 					+ '"' + ',')
	# 				file.write('"interface_description" : ' + '"' + field_tuple[4] + '"' + '},')
	# 			else:
	# 				file.write('{"interface_name" : ' + '"' + field_tuple[0] + '"' + ',')
	# 				file.write('"interface_address" : ' + '"' +field_tuple[1] + '"' + ',')
	# 				file.write('"interface_mask" : ' + '"' + field_tuple[2] + '"' + ',')
	# 				file.write('"network_id" : ' + '"' + field_tuple[3]
	# 					+ '"' + ',')
	# 				file.write('"interface_description" : ' + '"' + field_tuple[4] + '"' + '}')
	# 		file.write(']}')

	# 	with open(PATH_subnet_outputs + host + "_report_" + outfile_date + ".txt", 'w+') as file:
	# 		initial_line = '{:<15s} {:>20s} {:>20s} {:>20s} {:>40s}'.format('Name', 'Address', 'Mask', 'ID',
	# 				'Description')
	# 		file.write(initial_line + "\n")
	# 		for field_tuple in all_fields:
	# 			line = '{:<15s} {:>20s} {:>20s} {:>20s} {:>40s}'.format(field_tuple[0], field_tuple[1], 
	# 				field_tuple[2], field_tuple[3], field_tuple[4])
	# 			file.write(line + "\n")

	# 	for fields_tuple in all_fields:
	# 		#print fields_tuple
	# 		try:
	# 			NetworkID_object = NetworkID.objects.get(interface_name=fields_tuple[0], network_ID=fields_tuple[3],
	# 				hostname=host, mask=fields_tuple[2])
	# 		except ObjectDoesNotExist:
	# 			NetworkID_object = NetworkID(interface_name=fields_tuple[0], network_ID=fields_tuple[3],
	# 				hostname=host, mask=fields_tuple[2])
	# 			NetworkID_object.save()
	# 		else:
	# 			NetworkID_object.delete()
	# 			NetworkID_object = NetworkID(interface_name=fields_tuple[0], network_ID=fields_tuple[3],
	# 				hostname=host, mask=fields_tuple[2])
	# 			NetworkID_object.save()

# # def details(host_list)


# """
# Test function
# """

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
	#print hosts_info

# """
# Test function
# """

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
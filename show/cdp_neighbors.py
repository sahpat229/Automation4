import showCommands
import re
import threading
import math

class showThread(threading.Thread):
	def __init__(self, host, username, password, toggle, result, index):
		threading.Thread.__init__(self)
		self.host = host
		self.username = username
		self.password = password
		self.toggle = toggle

	# """
	# run function details the execution of threads
	# """
	def run(self):
		host = self.host
		username = self.username
		password = self.password
		toggle = self.toggle
		# """
		# Searches through show version command for Cisco Nexus Operating System to determine if the device is IOS
		# or NXOS
		# """
		NXOS = False
		if re.search('Cisco Nexus Operating System',
			showCommands.execute_str(host, username, password, 'show version')) != None:
			NXOS = True
		# thread.start_new_thread(showCommands.execute, ([host], username, password, ['term length 0', 'show ip int b | include up'],
		# 	[host+outfile_date+".txt"], ''))
		# thread.exit()
		#print PATH_subnet_outputs+host+"_"+outfile_date+".txt"
	

		# '''
		# Execute show cdp neighbor on each hosts and parse the outputs with reg
		# '''
		output_str = showCommands.execute_str(host, username, password, "show cdp neighbor")
		output = re.split("Port ID", output_str)[1]
		reg = "(Fas *[0-9/]*)|(Gig *[0-9/]*)|(Ten *[0-9/]*)|(mgmt *[0-9/]*)|(Eth *[0-9/]*)|(Port *[0-9]*)"
		outputs = re.split(reg, output)
		list_neighbor_names = []
		list_source_interfaces = []
		list_dest_interfaces = []
		
		counter = 0
		for index in range(len(outputs)):
			line = outputs[index]
			if counter == 14:
				counter = 0

			if counter == 0:
				list_neighbor_names.append(line.strip())

			if counter == 7:
				if line != None:
					if re.search("\n", line.strip()) != None:
						counter = 1
						list_dest_interfaces.append("")
						continue

			if 0 < counter < 7:
				if line != None:
					list_source_interfaces.append(line.strip())

			if 7 < counter < 14:
				if line != None:
					list_dest_interfaces.append(line.strip())

			counter += 1

		allzip = zip(list_neighbor_names, list_source_interfaces, list_dest_interfaces)
		results[index] = allzip


class UserException(Exception):
	def __init__(self, value):
		self.value = value
	def __str__(self):
		return self.value

#Generate a circular offset for the neighbors of the current host, i.e.,
#The neighbors will be in a circle around the current host
#This generates the offsets that you will add to the coordinates of the center
#of the host you're looking at currently
def circularOffset(number_of_neighbors):
	radius = float(number_of_neighbors * 200) / (2 * math.pi)
	angle = 0
	increment_angle = float(360)/float(number_of_neighbors)
	offset_tuples = []

	for index in range(number_of_neighbors):
		vertical_offset = radius * math.sin(angle)
		horizontal_offset = radius * math.cos(angle)
		offset_tuples.append((horizontal_offset, vertical_offset))
		angle += increment_angle

	return offset_tuples

"""
Get cdp takes a host, username, and password, execute show cdp neighbors
and then takes the output and stores the neighbor list, the local interface
name, and the remote interface name
"""

def get_cdp(host, username, password):

	'''
	Test if the device is NXOS or IOS
	'''
	NXOS = False
	if re.search('Cisco Nexus Operating System',
		showCommands.execute_str(host, username, password, 'show version')) != None:
		NXOS = True

	#Execute show cdp neighbor on the device
	output_str = showCommands.execute_str(host, username, password, "show cdp neighbor\n")
	#print output_str
	#Take out the extraneous 
	try:
		output = re.split("Port ID", output_str)[1]
	except Exception:
		raise UserException("No cdp neighbors")

	#Regexes to split things based on port names
	reg = "(Fas *[0-9/]*)|(Gig *[0-9/]*)|(Ten *[0-9/]*)|(mgmt *[0-9/]*)|(Eth *[0-9/]*)|(Port *[0-9]*)"
	outputs = re.split(reg, output)
	list_neighbor_names = []
	list_source_interfaces = []
	list_dest_interfaces = []
	
	#assign from the array after splitting to each of the three arrays
	#list_neighbor_names, list_source_interfaces, and list_dest_interfaces
	counter = 0
	for index in range(len(outputs)):
		line = outputs[index]
		if counter == 14:
			counter = 0

		if counter == 0:
			list_neighbor_names.append(line.strip())

		if counter == 7:
			#if the line isn't none, and if there's no enter in the line after
			#taking out extraneous whitespace from the sides, that means the neighbor
			#wasnt a cisco or other recognized device
			#(I.E, NAS server)
			if line != None:
				if re.search("\n", line.strip()) != None:
					counter = 1
					list_dest_interfaces.append("")
					continue

		if 0 < counter < 7:
			if line != None:
				list_source_interfaces.append(line.strip())

		if 7 < counter < 14:
			if line != None:
				list_dest_interfaces.append(line.strip())

		counter += 1

	number_of_neighbors = len(list_neighbor_names)
	offset_tuples = circularOffset(number_of_neighbors)
	allzip = zip(list_neighbor_names, list_source_interfaces, list_dest_interfaces, offset_tuples)
	return allzip

def cdp_neighbors(host_list, username, password):
	# results = [None] * len(host_list)
	# threads = []
	# for index in range(len(host_list)):
	# 	newThread = showThread(host, username, password, results, index)
	# 	newThread.start()
	# 	threads.append(newThread)


	# center coordinate "tracker"
	x_co = 0
	y_co = 0

	#host_nodes is a string that is almost JSON formatted, keeps tracks of nodes for the
	#topology graph
	host_nodes = ""
	#links is a string that is almsot JSON formatted, keeps tracks of the links for the
	#topology graph
	links = ""
	unique_host_list = host_list
	dict_of_zips = {}
	dict_of_centers = {}
	dict_of_ids = {}
	ignore_list = []

	for index in range(len(host_list)):
		host = host_list[index]
		dict_of_centers[host] = (x_co, y_co)
		dict_of_ids[host] = index
		host_nodes += '{"id" : ' + str(index) + ', "x" : ' +  str(x_co) + ', "y" : ' + str(y_co) + ', "name": "' + str(host) + '"},' 
		x_co += len(host_list) * 60

	counter = len(host_list)
	for index in range(len(host_list)):
		host = host_list[index]
		details = get_cdp(host, username, password)
		#print "DETAILS for", host, details
		dict_of_zips[host] =  details
		#print "DICT_OF_IDS: ", dict_of_ids
		for detail in details:
			neighbor_name = detail[0]
			source = detail[1]
			dest = detail[2]
			offsets = detail[3]
			if dest == "":
				continue
			
			# Basically to avoid duplicates if you have A and B, and you don't want to count the same link twice
			is_in_list = False
			which_one = ""
			for un_host in unique_host_list:
				if re.search(un_host, neighbor_name) != None:
					if un_host in host_list:
						ignore_list.append((un_host, host))
						
					is_in_list = True
					which_one = un_host
					break


			if not is_in_list:
				#print neighbor_name
				unique_host_list.append(neighbor_name)
				dict_of_ids[neighbor_name] = counter
				x_coordinate = dict_of_centers[host][0] + offsets[0]
				y_coordinate = dict_of_centers[host][1] + offsets[1]
				host_nodes += '{"id" : ' + str(counter) + ', "x" : ' +  str(x_coordinate) + ', "y" : ' + str(y_coordinate) + ', "name": "' + str(neighbor_name) + '"},' 

				links += '{"source" : ' + str(index) + ', "target" : ' + str(counter) + ', "src_port" : "' + str(source) + '", "dest_port" : "' + str(dest) + '"},'
				counter += 1
			#Same thing, to avoid duplicates
			else:
				skip = False
				for pair in ignore_list:
					if re.search(pair[0], host) != None:
						if re.search(pair[1], neighbor_name) != None:
							skip = True
				if skip:
					continue
				else:
					links += '{"source" : ' + str(index) + ', "target" : ' + str(dict_of_ids[which_one]) + ', "src_port" : "' + str(source) + '", "dest_port" : "' + str(dest) + '"},'


	return(host_nodes, links)
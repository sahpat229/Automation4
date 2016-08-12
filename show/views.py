from django.shortcuts import get_object_or_404, render
from django.http import HttpResponseRedirect, JsonResponse, HttpResponse
from django.core.urlresolvers import reverse, resolve

from django.contrib.staticfiles.views import serve
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ObjectDoesNotExist

from .models import TextFiles, HostFiles, NetworkID, AutomaticGen, PortModel
import json
import showCommands
import datetime
import text2html
import re
import logging
import os
import diff
import mimetypes
import clientCommands
import paramiko
import socket
import testCommand
import webbrowser
import subnet
import time
import crontab
import cdp_neighbors
from ports import generate_report
# Create your views here.

username = ""
privilege = ""

hostname = ""
password = ""
host_user = ""
logged_in = False


"""
PATH names for views to use.
base_path is a base string that corresponds to the path of the app
PATH_comm is the path for the lines field of TextFiles
PATH_host is the path for the lines field of HostFiles
PATH_outputs is the path for the file outputs of show_conf
PATH_compare is the path for the file outputs of compare_run
PATH_subnet_outputs is the path for the file outputs of subnet_outputs
PATH_subnet_compare is the path for the file outputs of subnet_compare
"""

base_path = os.getcwd() + '/show' #os.getcwd() gets the current working directory
PATH_comm = base_path + "/textfiles/"
PATH_host = base_path + '/hostlists/'
PATH_outputs = base_path + '/show_outputs/'
PATH_compare = base_path + '/compare_outputs/'
PATH_subnet_outputs = base_path+"/subnet_outputs/"
PATH_subnet_compare = base_path+"/subnet_compare/"
host_dictionary = {}  #made global so that subnet compare can access it
#cron = crontab.CronTab(user=True) #sets a new crontab for the user that django is running on


'''
Index page:

If the request is a GET request (i.e, the user typed in /show/index),
they get the default login page

If the request is a POST request (i.e, the user typed in their username
and password on the corresponding form), then this view validates the user
and depending on the user's privilege redirects them to either the admin
home page or the regular home page
'''

def index(request):
	if request.method == 'GET':
		return render(request, 'show/index.html')
	else:
		username = request.POST['username']
		password = request.POST['password']
		user = authenticate(username=username, password=password)
		if user is None:
			#context is used to pass on information to the HTML template
			context = {'error_msg': "Invalid username or password"}
			return render(request, 'show/index.html', context)
		else:
			login(request, user)
			#gets the html of home page and redirects them to it
			response = HttpResponseRedirect(reverse('show:list')) #Reverse builds the url corresponding to view list_options, list is
			#name of the url in the urls.py under the show directory
			return response

'''
Custom Exception class to return string values when catched
in later views.
'''

class UserException(Exception):
	def __init__(self, value):
		self.value = value
	def __str__(self):
		return self.value


'''
Admin Page:

View to display the admin page and handle all AJAX requests to the Admin Page.
The Admin Page handles modification of Users, TextFiles, HostFiles, and AutomaticGen database
instances through the corresponding Web Interface.  Note that Users are implemented
in django.contrib.auth.models, not custom implemented.
'''

@login_required #The decorator @login_required is used to tell DJango that the user must be logged in to access			# the view
def admin_page(request):

	# """
	# On a GET request, the view first tests if the user is an admin user, if not
	# then it returns an error message.  Otherwise, it shows the current lists of Users,
	# TextFiles, and HostFiles
	# """
	if request.method == 'GET':
		if request.user.is_superuser == False:
			return HttpResponse("Please log in as admin.")
		#list comprehension syntax, username_list will be a list of the usernames of all User objects
		username_list = [user.get_username() for user in User.objects.all()]
		#textfiles_list is a list of all the paths demarcated in the lines field of TextFiles objects
		textfiles_list = [(textfile.lines).replace(PATH_comm, "") for textfile in TextFiles.objects.all()]
		#hostfiles_list is a list of all the paths demarcated in the lines field of HostFiles objects
		hostfiles_list = [(hostfile.lines).replace(PATH_host, "") for hostfile in HostFiles.objects.all()]
		username_list.sort()
		textfiles_list.sort()
		hostfiles_list.sort()
		#autogen = AutomaticGen.objects.all()[0]
		context = {
			'username_list': username_list,
			'textfiles_list': textfiles_list,
			'hostfiles_list': hostfiles_list,}
			#'autobool' : autogen.daily,
			#'automin' : autogen.minute,
			#'autohour' : autogen.hour,
		
		return render(request, 'show/admin_page.html', context)

	# """
	# On a POST request, the view tests for certain keys and performs certain actions based
	# on the keys found
	# These POST request keys and values can be determined from the AJAX calls performed by the
	# page /templates/show/admin_page.html
	# """

	if request.method == 'POST':
		#print "IN ADMIN"

		# """
		# If the POST request has the key user_selection, that means the user clicked on a User
		# item in the list of Users, the view returns a JsonResponse containing the fields of the User
		# model so the webpage can display them
		# """

		if request.POST.has_key('user_selection'):
			selected_item = request.POST['user_selection']
			user = get_object_or_404(User, username=selected_item)
			return JsonResponse({'username': user.username, 'first_name': user.first_name,
				'last_name': user.last_name, 'email': user.email, 'is_superuser': str(user.is_superuser),
				'last_login': str(user.last_login), 'date_joined': str(user.date_joined)})

		# """
		# If the POST request has the key user_delete, that means the user clicked on a Delete button,
		# so the view deletes the selected object and returns a message whether it successfully deleted
		# the User or not
		# """

		elif request.POST.has_key('user_delete'):
			try:
				user_delete_item = request.POST['user_delete'].strip()
				user = get_object_or_404(User, username=user_delete_item)
				user.delete()
			except Exception:
				return JsonResponse({"err" : "Error occured"})
			else:
				username_list = [user_instance.username for user_instance in User.objects.all()]
				return JsonResponse({"success" : "success", "username_list" : username_list})

		# """
		# If the POST request has the key username, that means the user submitted a Form for the User
		# tab
		# """

		elif request.POST.has_key('username'):

			# """
			# If the POST request's value for the key type is none, that means the User is modifying
			# a current selected User.  The View tests whether the modified username is one that is already
			# taken, and if not it modifies the selected User and returns a response whether it was
			# successful or not.
			# """

			if request.POST['type'] == "none":
				try:
					user_list = User.objects.all()
					user = get_object_or_404(User, username=request.POST['original'])
					username_list = [instance.username for instance in user_list] #get all usernames
					username_list.remove(user.username) #remove the posted username
					if request.POST['username'] in username_list:
						raise UserException("Already a user with this username.")
					user.username = request.POST['username']
					user.first_name = request.POST['first_name']
					user.last_name = request.POST['last_name']
					user.email = request.POST['email']
					user.set_password(request.POST['password'])
					if request.POST['privilege'] == "Admin":
						user.is_superuser = True
					else:
						user.is_superuser = False
					#must save the user for it to be written to the database
					user.save()
				except UserException:
					return JsonResponse({'err': 'Already a user with this username.'})
				except Exception:
					return JsonResponse({'err': 'Other issue.'})
				else:
					user_list = User.objects.all()
					username_list = [instance.username for instance in user_list]
					return JsonResponse({'success': 'success', 'username_list' : username_list})

			# """
			# If the POST request's value for the key type is create, thta means the User is creating a new User.
			# The view tests whether the new username is one that is already taken, and if not it creates a User
			# with the entered fields.  The view returns a response as to whether it was successful or not.
			# """

			elif request.POST['type'] == "create":
				try:
					user_list = User.objects.all()
					username_list = [instance.username for instance in user_list]	
					if request.POST['username'] in username_list:
						raise UserException("Already a user with this username.")
					if request.POST['email'] == "":
						return JsonResponse({'err': 'No email entered'})
					user = User(username=request.POST['username'], first_name=request.POST['first_name'],
						last_name=request.POST['last_name'], email=request.POST['email'])
					if request.POST['privilege'] == "Admin":
						user.is_superuser = True
					else:
						user.is_superuser = False
					user.set_password(request.POST['password'])
					user.save()
				except UserException:
					return JsonResponse({'err' : 'Already a user with this username.'})
				except Exception:
					return JsonResponse({'err': 'Other issue.'})
				else:
					user_list = User.objects.all()
					username_list = [instance.username for instance in user_list]	
					return JsonResponse({'success' : 'success', 'username_list' : username_list})

		# """
		# If the POST request has the key file_selection, that means a TextFiles object was selected
		# and the view returns the fields for the TextFiles object so the webpage can display them
		# """

		elif request.POST.has_key('file_selection'):
			file_output = ""
			file_name = PATH_comm + request.POST['file_selection']
			try:
				textfile = TextFiles.objects.get(lines=file_name)
				with open(file_name, 'r') as file:
					file_output = file.read()
			except ObjectDoesNotExist:
				return JsonResponse({'file_open_err': 'No such file'})
			except Exception:
				return JsonResponse({'file_open_err': 'Could not read selected file'})
			else:
				return JsonResponse({'file_contents' : file_output, 'file_name' : request.POST['file_selection'], 
					'os': textfile.os,'func' : textfile.func})

		# """
		# If the POST request's type key has the value file_submit, that means a Form was submitted
		# for the TextFiles tab, and a TextFiles is being modified.  The view looks to see whether
		# the modified filename is already taken or if the combination of OS and Function is already taken,
		# and if not, modifies the TextFiles object appropriately and returns a JsonResponse detailing
		# whether there was an error or not, and if not, the list of new file names
		# """

		elif request.POST['type'] == "file_submit":
			try:
				list_of_files = TextFiles.objects.all()
				list_of_file_names = [file.lines.replace(PATH_comm, "") for file in list_of_files]
				orig_name = request.POST['original_text_file']
				list_of_file_names.remove(orig_name)
				#print request.POST['file_name']
				if (request.POST['file_name'] in list_of_file_names):
					raise UserException("File name already taken")
				this_file = TextFiles.objects.get(lines = (PATH_comm+request.POST['original_text_file']))
				try:
					compare_file = TextFiles.objects.get(os=request.POST['os_type'], func=request.POST['function'])
				except ObjectDoesNotExist:
					compare_file = None
				if (compare_file != None) and (compare_file != this_file):
					raise UserException("Commands for that OS and Function are already created")
				this_file.lines = PATH_comm + request.POST['file_name']
				this_file.os = request.POST['os_type']
				this_file.func = request.POST['function']
				with open(this_file.lines, 'w+') as file:
					file.write(request.POST['commands'])
				os.rename(PATH_comm + orig_name, PATH_comm + request.POST['file_name'])
				this_file.save()
			except ObjectDoesNotExist:
				return JsonResponse({'file_open_err' : 'No such file'})
			except UserException as err:
				return JsonResponse({'file_open_err' : err.value})
			else:
				list_of_files = TextFiles.objects.all()
				list_of_file_names = [file.lines.replace(PATH_comm, "") for file in list_of_files]
				return JsonResponse({'file_open_err' : 'success', 'list_of_file_names' : list_of_file_names})

		# """
		# If the POST request's type key has the value file_create, that means a TextFiles is being created.
		# The view looks to see whether the new filename is already taken or if the combination of OS and Function
		# is already taken, and if not, it creates a new TextFiles object and returns a JsonResponse detailing
		# whether there was an error or not, and if not, the list of new file names
		# """

		elif request.POST['type'] == "file_create":
			try:
				list_of_files = TextFiles.objects.all()
				list_of_file_names = [file.lines.replace(PATH_comm, "") for file in list_of_files]
				if (request.POST['file_name'] in list_of_file_names):
					raise UserException("File name already taken")
				try:
					compare_file = TextFiles.objects.get(os=request.POST['os_type'], func=request.POST['function'])
				except ObjectDoesNotExist:
					compare_file = None
				if (compare_file != None):
					raise UserException("Commands for that OS and Function are already created")
				file_name = request.POST['file_name']
				os_type = request.POST['os_type']
				function = request.POST['function']
				new_file = TextFiles(lines=(PATH_comm + file_name), os=os_type, func=function)
				with open((PATH_comm+file_name), 'w+') as newfile:
					newfile.write(request.POST['commands'])
				new_file.save()
			except UserException as err:
				return JsonResponse({'file_open_err' : err.value})
			else:
				list_of_files = TextFiles.objects.all()
				list_of_file_names = [file.lines.replace(PATH_comm, "") for file in list_of_files]
				return JsonResponse({'file_open_err' : 'success', 'list_of_file_names' : list_of_file_names})

		# """
		# If the POST request's type key has the value file_delete, that means a TextFiles is being created.
		# The view deletes the appropriate object and returns a JsonResponse detailing
		# whether there was an error or not, and if not, the list of new file names
		# """
		elif request.POST['type'] == "file_delete":
			try:
				this_file = TextFiles.objects.get(lines=(PATH_comm + request.POST['file_delete']))
				this_file.delete()
				os.remove(PATH_comm + request.POST['file_delete'])
			except Exception:
				return JsonResponse({"file_open_err": 'Error in Deletion'})
			else:
				list_of_files = TextFiles.objects.all()
				list_of_file_names = [file.lines.replace(PATH_comm, "") for file in list_of_files]
				return JsonResponse({'file_open_err' : 'success', 'list_of_file_names': list_of_file_names})

		# """
		# All the statements are below serve the exact same function as those for TextFiles, except for HostFiles,
		# since HostFiles and TextFiles have the same fields.
		# """


		elif request.POST.has_key('host_selection'):
			host_output = ""
			hostfile_name = PATH_host + request.POST['host_selection']
			try:
				hostfile = HostFiles.objects.get(lines=hostfile_name)
				with open(hostfile_name, 'r') as file:
					host_output = file.read()
			except ObjectDoesNotExist:
				return JsonResponse({'host_open_err': 'No such hostfile'})
			except Exception:
				return JsonResponse({'host_open_err': 'Could not read selected hostfile'})
			else:
				return JsonResponse({'host_contents' : host_output, 'file_name' : request.POST['host_selection'], 
					'os': hostfile.os,'func' : hostfile.func})
		elif request.POST['type'] == 'host_delete':
			try:
				this_hostfile = HostFiles.objects.get(lines=(PATH_host + request.POST['host_delete']))
				this_hostfile.delete()
				os.remove(PATH_host + request.POST['host_delete'])
			except Exception:
				return JsonResponse({"host_open_err": 'Error in Deletion'})
			else:
				list_of_files = HostFiles.objects.all()
				list_of_file_names = [file.lines.replace(PATH_host, "") for file in list_of_files]
				return JsonResponse({'host_open_err' : 'success', 'list_of_file_names': list_of_file_names})			
		elif request.POST['type'] == 'host_submit':
			try:
				list_of_files = HostFiles.objects.all()
				list_of_file_names = [file.lines.replace(PATH_host, "") for file in list_of_files]
				orig_name = request.POST['original_host_file']
				list_of_file_names.remove(orig_name)
				#print request.POST['host_file_name']
				if (request.POST['host_file_name'] in list_of_file_names):
					raise UserException("File name already taken")
				this_file = HostFiles.objects.get(lines = (PATH_host+request.POST['original_host_file']))
				try:
					compare_file = HostFiles.objects.get(os=request.POST['os_type'], func=request.POST['function'])
				except ObjectDoesNotExist:
					compare_file = None
				if (compare_file != None) and (compare_file != this_file):
					raise UserException("Hosts for that OS and Function are already created")
				this_file.lines = PATH_host + request.POST['host_file_name']
				this_file.os = request.POST['os_type']
				this_file.func = request.POST['function']
				if (re.search('[0-9]{1, 3}\.[0-9]{1, 3}\.[0-9]{1, 3}\.[0-9]{1,3}', request.POST['hosts'])) != None:
					raise UserException('Do not enter an IP Address!')
				with open(this_file.lines, 'w+') as file:
					file.write(request.POST['hosts'])
				os.rename(PATH_host + orig_name, PATH_host + request.POST['host_file_name'])
				this_file.save()
			except ObjectDoesNotExist:
				return JsonResponse({'host_open_err' : 'No such file'})
			except UserException as err:
				return JsonResponse({'host_open_err' : err.value})
			else:
				list_of_files = HostFiles.objects.all()
				list_of_file_names = [file.lines.replace(PATH_host, "") for file in list_of_files]
				return JsonResponse({'host_open_err' : 'success', 'list_of_file_names' : list_of_file_names})
		elif request.POST['type'] == "host_create":
			try:
				list_of_files = HostFiles.objects.all()
				list_of_file_names = [file.lines.replace(PATH_host, "") for file in list_of_files]
				if (request.POST['host_file_name'] in list_of_file_names):
					raise UserException("File name already taken")
				try:
					compare_file = HostFiles.objects.get(os=request.POST['os_type'], func=request.POST['function'])
				except ObjectDoesNotExist:
					compare_file = None
				if (compare_file != None):
					raise UserException("Commands for that OS and Function are already created")
				file_name = request.POST['host_file_name']
				os_type = request.POST['os_type']
				function = request.POST['function']
				new_file = HostFiles(lines=(PATH_host + file_name), os=os_type, func=function)
				with open((PATH_host+file_name), 'w+') as newfile:
					newfile.write(request.POST['hosts'])
				new_file.save()
			except UserException as err:
				return JsonResponse({'host_open_err' : err.value})
			else:
				list_of_files = HostFiles.objects.all()
				list_of_file_names = [file.lines.replace(PATH_host, "") for file in list_of_files]
				return JsonResponse({'host_open_err' : 'success', 'list_of_file_names' : list_of_file_names})


		#Basically if else: was above these statements, since everything else would return before it reached here.
		#Delete all previous AutomaticGen instances, we only want to enter a crontable entry correspondong to the current
		#Admin post request
		AutomaticGen.objects.all().delete()
		#Delete all jobs from the cron (there should only be one but this takes care of the "just in case") 
		cron.remove_all()
		daily = request.POST['daily']
		hour = request.POST['hour']
		minute = request.POST['minute']
		# have to test for string false because javascript type is different
		if daily=='false':
			autogen = AutomaticGen(daily=False, hour=0, minute=0)
		else:
			autogen = AutomaticGen(daily=True, hour=hour, minute=minute)
		autogen.save()
		username = request.POST['username']
		password = request.POST['password']
		
		# add to the crontable to execute subnet_exec with the appropriate arguments at the specified time
		if (daily == 'true'):
			host_list = ""
			for hostlistfile in HostFiles.objects.all():
				with open(hostlistfile.lines, 'r') as host_list_file:
					for host in host_list_file:
						host_list += host.strip() + " "
			# except Exception:
			# 	print "IN ERR"
			# 	return JsonResponse({'selection_err' : 'Error in host population'})
			job = cron.new(command=base_path + "/subnet_exec.py --hosts " +
				host_list + "--username " + username + " --password " + password)
			job.setall(minute, hour, '*', '*', '*')
			cron.write()
			# for job in cron:
			# 	print job
			return JsonResponse({'success' : 'success'})
		else:
			return JsonResponse({'success': 'success'})



@login_required
def list_options(request):
	if request.user.is_superuser:
		context = {"privilege" : "superuser"}
	else:
		context = {'privilege' : 'user'}
	return render(request, 'show/list.html', context)

'''
 Output Repository Page
If the request method is a GET request (i.e, the user just 
accessed this page through the dropdown menu), then it renders
the default show config page

If the request method is a POST, then it tests which form was posted,
if the post has the key 'os', then it was the left form that was posted
and the view returns a JsonResponse with a
list of possible commands and hosts that correspond
with the OS and Function that was selected.

If the post has the key 'hostname', 'username', 'password', and 'lines',
then it was the right form that was posted and the view returns an
HTML file as an attachment that is the result of running the commands
on the chosen host
'''
@login_required
def show_conf(request):
	if request.method == 'GET':
		#Check if admin
		if request.user.is_superuser:
			context = {'privilege': 'superuser'}
		else:
			context = {'privilege': 'user'}
		return render(request, 'show/show.html', context)
	if request.method == 'POST':
		#choosing OS and Func type, and getting list of hosts and lists of commands
		if request.POST.has_key('os'):
			os = request.POST['os']
			function = request.POST['function']
			#get the TextFiles and HostFiles objects
			try:
				textfile = TextFiles.objects.get(os=os, func=function)
			except ObjectDoesNotExist:
				return JsonResponse({'selection_err': 'CLI-file for ' + os + ' and ' + function +
					' does not exist'})
			try:
				hostlistfile = HostFiles.objects.get(os=os, func=function)
			except ObjectDoesNotExist:
				return JsonResponse({'selection_err': 'Hostfile for ' + os + ' and ' + function +
					' does not exist'})

			#read the contents of the textfiles referred to by the lines field of TextFiles and HostFiles
			#and return them to the webpage for display 
			with open(textfile.lines, 'r') as lines, open(hostlistfile.lines, 'r') as host_list:
				textlines = [line for line in lines]
				host_list = [host for host in host_list]
				return JsonResponse({'lines': textlines, 'hosts': host_list})

		#choosing commands, and hosts to execute the commands on
		else:
			if request.POST.has_key('host_total') and request.POST.has_key('password') and \
				request.POST.has_key('username') and request.POST.has_key('lines'):
					host_lines = request.POST['host_total']
					password = request.POST['password']
					host_user = request.POST['username']
					lines = request.POST['lines']
					tags_remarks = request.POST['tags_remarks']
					#Get host names
					hosts = re.split("\n", host_lines)
					hosts = hosts[0:(len(hosts) - 1)]
					#get commands
					commands = re.split("\n", lines)
					commands = commands[0:(len(commands) - 1)]
					#Generate list of outputfilenames
					outputfilename = ""
					for item in re.split(' ', str(datetime.datetime.now())):
						outputfilename = outputfilename + item + "_"
					outputfilenames = [(hostname + "_" + outputfilename) for hostname in hosts]
					path = PATH_outputs
					filenames = [(path + filename + ".txt") for filename in outputfilenames]
					#execute the commands on the hosts
					try:
						showCommands.execute(hosts, host_user, password, 
							commands, filenames, tags_remarks)
					except showCommands.IPException as err:
						return JsonResponse({'error': err.value})
					else:
						data = {'data': []}	
						for filename in outputfilenames:
							#convert textfiles to html			
							text2html.text2html(path + filename+".txt", path + filename+".html")
							url = request.build_absolute_uri(reverse('show:show_file_show', args=(filename + ".html", )))
							data['data'].append(url)
						#give url to html page
						return JsonResponse(data)
			else:
				return JsonResponse({'error': 'Please input a hostname, password, username' +
					', and select at least one command'})

'''
Compare Previous Outputs Page
If the request method is a GET request, it displays the webpage with the
list_items passed to it through the context variable.  list_items is a list
of all previous outputs generated from the output_repository

If the request method is a POST request, the user selected two items
to be compared, and the view generates an HTML diff of the two and
displays that to the user
'''

@login_required
def compare_run(request):
	if request.method == 'GET':
		#test privilege of user
		if request.user.is_superuser:
			context = {'privilege' : 'superuser'}
		else:
			context = {'privilege': 'user'}
		list_items = []
		#generate list_items
		for item in os.listdir(PATH_outputs):
			if re.search('.txt', item) != None:
				list_items.append(item)
		list_items.sort()
		context['list_items'] = list_items
		return render(request, 'show/compare_run.html', context)

	if request.method == 'POST':
		compare_hostname = ""
		#search functionality user inputs a name, gets put for the POST['hostname']
		if request.POST.has_key('hostname'):
			compare_hostname = request.POST['hostname']
			matched_items = []
			items = os.listdir(PATH_outputs)
			items.sort()
			for item in items:
				match = compare_hostname
				if re.search(match, item) != None:
					if re.search('.txt', item) != None:
						matched_items.append(item)
			return JsonResponse({'matched_items': matched_items})

		#compare and generate functionality
		else:
			#find out which files
			line_total = request.POST['lines']
			lines = re.split('\n', line_total)
			lines = lines[0: (len(lines) - 1)]
			if len(lines) != 2:
				return JsonResponse({'line_err_msg': "Please pick only two items."})
			path = PATH_outputs
			path_comp = PATH_compare
			#generate outputfilenames
			outputfilename = ""
			items = re.split(' ', str(datetime.datetime.now()))
			for item in re.split(' ', str(datetime.datetime.now())):
				outputfilename = outputfilename + item + "_"
			outputfilename = "compare" + outputfilename + compare_hostname +".html"
			#generate diff
			diff.diff(path+lines[0], path+lines[1], path_comp+outputfilename)
			url = request.build_absolute_uri(reverse('show:compare_file_show', args=(outputfilename, )))
			#give url to html page
			return JsonResponse({'data': url})

"""
returns the an HttpResponse containg the contents of the file parsed
from the url regex.  the parsed file_name is entered into the argument
file_name.  Used to display the contents of the outputs from running
commands on the hosts
"""

@login_required
def show_file_show(request, file_name):
	path_comp = PATH_outputs
	openfile = open(path_comp + file_name, 'r')
	response = HttpResponse(openfile.read())
	openfile.close()
	return response

"""
same as show_file_show but for outputs from the Compare Site
"""

@login_required
def compare_file_show(request, file_name):
	path_comp = PATH_compare
	openfile = open(path_comp + file_name, 'r')
	response = HttpResponse(openfile.read())
	openfile.close()
	return response

@login_required
def push_configs(request):
	if request.method == 'GET':
		return render(request, 'show/push_configs.html')

"""
Generate the outputs for a set of hosts.
"""

@login_required
def subnet_outputs(request):

	"""
	If the request is a GET request just return the page with the privilege context
	"""

	if request.method == 'GET':
		if request.user.is_superuser:
			context = {'privilege': 'superuser'}
		else:
			context = {'privilege': 'user'}
		return render(request, 'show/subnet_outputs.html', context)

	# """
	# If the request is a POST request
	# """
	elif request.method == 'POST':

		# """
		# If os and function were posted, return a JsonResponse with either an error is the HostFile can't be opened up
		# or return the appropriate list of hosts.
		# """
		if request.POST.has_key('os'):
			os = request.POST['os']
			function = request.POST['function']

			# """
			# if the user selected "All" and "All" for os and function, give them a list of all hosts
			# """
			if (os=="All") and (function == "All"):
				host_list = []
				try:
					for hostlistfile in HostFiles.objects.all():
						with open(hostlistfile.lines, 'r') as host_list_file:
							host_list += [host for host in host_list_file]
				except Exception:
					return JsonResponse({'selection_err' : 'Error in host population'})
				else:
					return JsonResponse({'hosts': host_list})


			elif (os=="All") and (function != "All"):
				host_list = []
				#print "HERE: "
				try:
					#print "LIST: ", list(HostFiles.objects.filter(func=function))
					for hostlistfile in list(HostFiles.objects.filter(func=function)):
						with open(hostlistfile.lines, 'r') as host_list_file:
							host_list += [host for host in host_list_file]
				except Exception as e:
					return JsonResponse({'selection_err' : 'Error in host population'})
				else:
					return JsonResponse({'hosts': host_list})

			elif (os!="All") and (function == "All"):
				host_list = []
				try:
					for hostlistfile in list(HostFiles.objects.filter(os=os)):
						with open(hostlistfile.lines, 'r') as host_list_file:
							host_list += [host for host in host_list_file]
				except Exception as e:
					return JsonResponse({'selection_err' : 'Error in host population'})
				else:
					return JsonResponse({'hosts': host_list})
			#get the TextFiles and HostFiles objects
			else:
				try:
					hostlistfile = HostFiles.objects.get(os=os, func=function)
				except ObjectDoesNotExist:
					return JsonResponse({'selection_err': 'Hostfile for ' + os + ' and ' + function +
						' does not exist'})

			#read the contents of the textfiles referred to by the lines field of TextFiles and HostFiles
			#and return them to the webpage for display 
				with open(hostlistfile.lines, 'r') as host_list_file:
					host_list = [host for host in host_list_file]
					return JsonResponse({'hosts': host_list})

		# """
		# Conditional for when the user POSTs a list of all the hosts that they want to generate outputs for
		# """
		elif request.POST.has_key('host_lines'):
			hostlines = request.POST['host_lines']
			username = request.POST['username']
			password = request.POST['password']
			hosts = re.split("\n", hostlines)
			hosts = hosts[0:(len(hosts) - 1)]
			#print hosts, username, password
			try:
				#print "HI"
				# """
				# subnet.execute is the script that generates the outputs
				# """
				subnet.execute(hosts, username, password)
				#print "Hello"
			except Exception:
				return JsonResponse({'error' : 'Error in execution'})
			else:
				return JsonResponse({'error' : 'Access generated reports in Subnet Locator tab.'})
				#print "BYE"

# """
# Compare two IP addresses, if ip_address1 is greater than 2, returns 1, if less returns -1, if same, returns 0
# """


def compare_ips(ip_address1, ip_address2):
	fields1 = re.split('\.', ip_address1)
	fields1 = map(int, fields1)
	fields2 = re.split('\.', ip_address2)
	fields2 = map(int, fields2)

	greater = 0
	for index in range(len(fields1)):
		field1 = fields1[index]
		field2 = fields2[index]
		if field1 > field2:
			greater = 1
			break
		if field1 < field2:
			greater = -1
			break

	return greater

mapper = {'0' : 0, '128' : 1, '192' : 2, '224' : 3, '240' : 4, '248' : 5, '252' : 6, '254' : 7, '255' : 8}

# """
# returns True if ip_address is within the range of NetwkID_object's IP range
# """

def isWithinRange(ip_address, NetwkID_object):
	object_ip = NetwkID_object.network_ID
	object_mask = NetwkID_object.mask
	#get the mask_fields
	mask_fields = re.split('\.', object_mask)
	#gets the total number of "1s" in the mask, ex: 255.255.255.0 has 24 1's since its -> 1(x24).00000000 in binary
	total_ones = 0
	for mask_field in mask_fields:
		total_ones += mapper[mask_field]

	#get each of the ip_fields of the object_ip and the entered address and convert each field from a string to an int
	object_ip_fields = re.split('\.', object_ip)
	object_ip_fields = map(int, object_ip_fields)
	ip_address_fields = re.split('\.', ip_address)
	ip_address_fields = map(int, ip_address_fields)

	object_string = ""
	ip_string = ""
	#change each of the decimal field strings to binary strings and store them in object_string and ip_string
	for index in range(len(object_ip_fields)):
		object_field = object_ip_fields[index]
		ip_field = ip_address_fields[index]
		object_string += format(object_field, '008b')
		ip_string += format(ip_field, '008b')

	#go through the first (total_ones) amount of characters in object_string and ip_string, if there's any differences,
	#then ip_address is not in the range of NetwkID_object	
	for i in range(total_ones):
		if (object_string[i] != ip_string[i]):
			return False

	return True

# """
# Gets the closest NetworkID object to ip_address
# """

def getNetworkModel(ip_address):
	#list_netwk_ids is a list of all the Network ID's present in the database (i.e. subnet IDs)
	list_netwk_ids = [netwk_object.network_ID for netwk_object in NetworkID.objects.all()]
	#sort list_netwk_ids using the compare_ips comparator
	list_netwk_ids = sorted(list_netwk_ids, cmp=compare_ips)
	# Linear Search, can be modified to a logarithmic search in the future
	#print list_netwk_ids

	start = 0
	end = len(list_netwk_ids) - 1
	mid = 0

	#binary search for the closest network ID, end is the index of the resulting network ID
	while (start <= end):
		mid = (start + end) / 2
		this_id = list_netwk_ids[mid]
		if this_id == ip_address:
			break
		elif compare_ips(this_id, ip_address) == 1:
			end = mid - 1
		elif compare_ips(this_id, ip_address) == -1:
			start = mid + 1


	# counter = 0
	# for index in range(len(list_netwk_ids)):
	# 	netwk_id = list_netwk_ids[index]
	# 	print "NETWK ID", netwk_id
	# 	if compare_ips(ip_address, netwk_id) == -1:
	# 		break
	# 	counter += 1
	# index_of_closest = counter - 1
	closest_network_id = list_netwk_ids[end]
	#print "CLOSEST: ", closest_network_id

	#get a list of all NetworkID objects that have closest_network_id as its network_ID
	comparing_objects = list(NetworkID.objects.filter(network_ID=closest_network_id))

	#accomadation for if comparing_objects contains mutliple objects
	if isinstance(comparing_objects, list):
		comparing_object = comparing_objects[0]
	else:
		comparing_object = comparing_objects

	#check whether ip_address is actualy within range of its closest neighbor, if it is then it should belong to that network ID
	if isWithinRange(ip_address, comparing_object):
		return comparing_objects

	else:
		return None

# """
# subnet_compare is the view that corresponds to the user either selecting an network ID, searching for a networkID,
# or comparing a networkID's current state to its past state
# """


def subnet_compare(request):

	"""
	On a GET request, should return a rendered HTML page with all the hostnames that have outputs generated for them
	"""

	if request.method == "GET":
		host_dictionary = {}
		if request.user.is_superuser:
			context = {'privilege': 'superuser'}
		else:
			context = {'privilege': 'user'}

		host_names = []
		#get all items in subnet outputs and sort them
		list_items = os.listdir(base_path + "/subnet_outputs/")
		list_items.sort()

		#add the host_name field to host_names list
		for item in list_items:
				if re.search('.json', item) != None:
					[host_name, date] = re.split('(?:_detail_)*(?:_.json)*', item)[0:2]
					if not host_name in host_names:
						host_names.append(host_name)

		#pass the host_names list to the site to render
		context['hostnames'] = host_names
		return render(request, 'show/subnet_compare.html', context)


	# """
	# On a POST request
	# """

	if request.method == "POST":

		# """
		# If the user is selecting a hostname from the initial list of host names,
		# pass a list of dates for the HTML page to display in the dates list container
		# """

		if request.POST['type'] == "host_select":
			post_hostname = request.POST['hostname']
			#print post_hostname
			list_items = os.listdir(base_path + "/subnet_outputs/")
			list_items.sort()
			list_dates = []
			for item in list_items:
				if re.search('.json', item) != None:
					[host_name, date] = re.split('(?:_detail_)*(?:_.json)*', item)[0:2]
					if host_name == post_hostname:
						list_dates.append(date)
			list_dates.sort()
			return JsonResponse({'dates' : list_dates})

		# """
		# If the user is selecting a date or selecting one dates, return a JsonResponse with all the
		# details for each interface that are in JSON format

		# If the user is selecting two dates, return both sets of data and a url which will give them
		# a HTML text diff between the two detailed reports

		# """

		elif request.POST['type'] == "dates_submit":
			dates_lines = request.POST['dates_lines']
			host = request.POST['host']
			dates = re.split('\n*', dates_lines)
			dates = dates[0: len(dates)-1]
			subnet_path = base_path + "/subnet_outputs/"
			#print dates
			# """
			# If the user only submitted one date
			# """
			if len(dates) == 1:
				name_of_file = host + "_detail_" + dates[0] + "_.json"
				json_data = ""
				# """
				# Read the JSON details are return it
				# """
				with open(base_path + "/subnet_outputs/" + name_of_file, 'r') as file:
					json_data = file.read()
				return JsonResponse({'data' : json_data, 'type_dates' : 'one'})
			# """
			# If the user submitted two dates
			# """
			elif len(dates) == 2:
				name_of_file_1 = host+"_detail_" + dates[0] + "_.json"
				name_of_file_2 = host+"_detail_" + dates[1] + "_.json"
				compare_1 = host+"_report_" + dates[0] + "_.txt"
				compare_2 = host+"_report_" + dates[1] + "_.txt"
				json_data_1 = ""
				json_data_2 = ""
				outfile_date = ""
				# """
				# Generate a string denoting the current time
				# """
				for item in re.split(' ', str(datetime.datetime.now())):
					outfile_date += item + "_"
				outputfilename = host + '_compare_' + outfile_date + "_.html"
				# """
				# Read both JSON details
				# """
				with open(base_path + "/subnet_outputs/" + name_of_file_1, 'r') as file1:
					json_data_1 = file1.read()
				with open(base_path + "/subnet_outputs/" + name_of_file_2, 'r') as file2:
					json_data_2 = file2.read()
				# """
				# Construct a HTML diff of the reports
				# """
				diff.diff(subnet_path + compare_1, subnet_path + compare_2,
					base_path + "/subnet_compare/" +outputfilename)
				url = request.build_absolute_uri(reverse('show:subnet_file_show', args=(outputfilename, )))
				return JsonResponse({'data1': json_data_1, 'data2': json_data_2, 'type_dates' : 'two', 'url': url})
			else:
				return JsonResponse({'type_dates' : 'error'})

		# """
		# If the user searched for an IP, return the appropriate details
		# """

		elif request.POST['type'] == "search":
			ip_search_address = request.POST['ip_address']
			# """
			# Get the NetworkID models that have ip_search_address within it's range
			# """
			closest_objects = getNetworkModel(ip_search_address)
			if closest_objects == None:
				return JsonResponse({'error' : 'No Match Found'})

			# """
			# If closest_objects is a list, get strings for all the hostnames, ids, masks, and interface_names for each network_model
			# in closet_objects
			# """
			elif isinstance(closest_objects, list):
				hostnames = ""
				ids = ""
				masks = ""
				interface_names = ""
				for instance in closest_objects:
					hostnames += instance.hostname + "\n"
					ids += instance.network_ID + "\n"
					masks += instance.mask + "\n"
					interface_names += instance.interface_name + "\n"
				#print hostnames, ids, masks, interface_names
			
			else:
				hostnames = closest_objects.hostname
				ids = closest_object.network_ID
				masks = closest_object.mask
				interface_names = closest_object.interface_name

			return JsonResponse({'network_id' : ids, 'hostname' : hostnames,'mask' : masks, 
				'interface_name' : interface_names, 'status': 'success'})
			
# """
# Return the diff file specified by file_name, parsed from the url
# """


@login_required
def subnet_file_show(request, file_name):
	openfile = open(PATH_subnet_compare + file_name, 'r')
	response = HttpResponse(openfile.read())
	openfile.close()
	return response

# graphs the complete topology using Cisco Next UI
# graphs the topology of hosts that the user indicates
@login_required
def topology_mapper(request):
	if request.method == "GET":
		if request.user.is_superuser:
			context = {'privilege': 'superuser'}
		else:
			context = {'privilege': 'user'}
		return render(request, 'show/topology_mapper.html', context)

	elif request.method == "POST":
		# """
		# If os and function were posted, return a JsonResponse with either an error is the HostFile can't be opened up
		# or return the appropriate list of hosts.
		# """
		if request.POST.has_key('os'):
			os = request.POST['os']
			function = request.POST['function']

			# """
			# if the user selected "All" and "All" for os and function, give them a list of all hosts
			# """
			if (os=="All") and (function == "All"):
				host_list = []
				try:
					for hostlistfile in HostFiles.objects.all():
						with open(hostlistfile.lines, 'r') as host_list_file:
							host_list += [host for host in host_list_file]
				except Exception:
					return JsonResponse({'selection_err' : 'Error in host population'})
				else:
					return JsonResponse({'hosts': host_list})


			elif (os=="All") and (function != "All"):
				host_list = []
				#print "HERE: "
				try:
					#print "LIST: ", list(HostFiles.objects.filter(func=function))
					for hostlistfile in list(HostFiles.objects.filter(func=function)):
						with open(hostlistfile.lines, 'r') as host_list_file:
							host_list += [host for host in host_list_file]
				except Exception as e:
					return JsonResponse({'selection_err' : 'Error in host population'})
				else:
					return JsonResponse({'hosts': host_list})

			elif (os!="All") and (function == "All"):
				host_list = []
				try:
					for hostlistfile in list(HostFiles.objects.filter(os=os)):
						with open(hostlistfile.lines, 'r') as host_list_file:
							host_list += [host for host in host_list_file]
				except Exception as e:
					return JsonResponse({'selection_err' : 'Error in host population'})
				else:
					return JsonResponse({'hosts': host_list})
			#get the TextFiles and HostFiles objects
			else:
				try:
					hostlistfile = HostFiles.objects.get(os=os, func=function)
				except ObjectDoesNotExist:
					return JsonResponse({'selection_err': 'Hostfile for ' + os + ' and ' + function +
						' does not exist'})

			#read the contents of the textfiles referred to by the lines field of TextFiles and HostFiles
			#and return them to the webpage for display 
				with open(hostlistfile.lines, 'r') as host_list_file:
					host_list = [host for host in host_list_file]
					return JsonResponse({'hosts': host_list})
		
		#Get hosts selected by the user and return the CDP neighbors JSON
		elif request.POST.has_key('host_lines'):
			hostlines = request.POST['host_lines']
			username = request.POST['username']
			password = request.POST['password']
			hosts = re.split("\n", hostlines)
			hosts = hosts[0:(len(hosts) - 1)]
			#print hosts, username, password
			#try:
				#print "HI"
				# """
				# subnet.execute is the script that generates the outputs
				# """
			try:
				(nodes, links) = cdp_neighbors.cdp_neighbors(hosts, username, password)
			except cdp_neighbors.UserException as err:
				return JsonResponse({'error': err.value})
			#except Exception:
			#	return JsonResponse({'error' : 'Error in execution'})
			#else:
				#Delete the last character, a comma from the nodes string and links string
				#Append it to outputstr for proper format for Cisco API
			outputstr = ""
			nodes = nodes[: -1]
			links = links[: -1]
			outputstr += '{ "nodes" : [' + nodes + '], "links": [' + links + ']}'
			return JsonResponse({'success' : 'success', 'data': outputstr})
			#print "BYE"
	

"""
Compare Dates
"""


def date_compare(first_date, second_date):
	first_fields = re.split('-', first_date)
	second_fields = re.split('-', second_date)
	first_fields = map(int, first_fields)
	second_fields = map(int, second_fields)
	for index in range(len(first_fields)):
		if first_fields[index] > second_fields[index]:
			return 1
		elif first_fields[index] < second_fields[index]:
			return -1
	return 0

"""
Generator to get different rgb values for different hosts
"""


def yield_rgb():
	static_numbs = [10, 10, 10]
	while True:
		for index in range(3):
			static_numbs[index] += 25
			if static_numbs[index] >= 250:
				static_numb[index] = 10

		yield static_numbs
	
"""
Port utilization graph
"""


@login_required
def ports(request):
	generator = yield_rgb()
	if request.method == "GET":
		if request.user.is_superuser:
			context = {'privilege': 'superuser'}
		else:
			context = {'privilege': 'user'}
		list_names = []

		for instance in PortModel.objects.all():
			if instance.hostname in list_names:
				continue
			else:
				list_names.append(instance.hostname)

		context['hostnames'] = list_names

		return render(request, 'show/ports_compare.html', context)

	elif request.method == "POST":
		if request.POST['type'] == 'generation':
			hosts = request.POST['host_lines']
			hosts = re.split('\n', hosts)
			del hosts[-1]
			#try:
			generate_report(hosts, request.POST['username'], request.POST['password'])
			#except Exception:
			#	return JsonResponse({'error' : 'Error in Execution'})
			#else:
			return JsonResponse({'error': 'Success'})

		elif request.POST['type'] == 'selection':
			hosts = request.POST['host_lines']
			hosts = re.split('\n', hosts)
			print hosts
			del hosts[-1]

			list_labels = []
			for host in hosts:
				list_of_instances = list(PortModel.objects.filter(hostname=host))
				for instance in list_of_instances:
					if instance.date in list_labels:
						continue
					else:
						list_labels.append(instance.date)

			list_labels = sorted(list_labels, cmp=date_compare)
			dict_labels_to_index = {}
			for index in range(len(list_labels)):
				label = list_labels[index]
				dict_labels_to_index[label] = index

			data = {}
			data['labels'] = list_labels
			data['datasets'] = []

			datasets_connected = [None]*len(hosts)
			datasets_notconnected = [None] * len(hosts)

			for index in range(len(hosts)):
				first_numbs = next(generator)
				second_numbs = next(generator)
				local_connected_dict = {}
				local_connected_dict['data'] = [None]*len(list_labels)
				local_notconnected_dict = {}
				local_notconnected_dict['data'] = [None]*len(list_labels)
				host = hosts[index]
				list_of_instances = list(PortModel.objects.filter(hostname=host))
				local_connected_dict['label'] = host + " Connected"
				local_connected_dict['fill'] = 'false'
				local_connected_dict['lineTension'] = 0.1
				local_connected_dict['backgroundColor'] = "rgba("+str(first_numbs[0]) +"," + str(first_numbs[1]) + "," + str(first_numbs[2]) + ", 0.4)"
				local_connected_dict['borderColor'] = "rgba(75, 192, 192, 1)"
				local_connected_dict['pointRadius'] = 4
				local_connected_dict['spanGaps'] = 'true'
				local_notconnected_dict['label'] = host + " Not Connected"
				local_notconnected_dict['fill'] = 'false'
				local_notconnected_dict['lineTension'] = 0.1
				local_notconnected_dict['backgroundColor'] = "rgba("+str(second_numbs[0]) +"," + str(second_numbs[1]) + "," + str(second_numbs[2]) + ", 0.4)"
				local_notconnected_dict['borderColor'] = "rgba(955, 192, 192, 1)"
				local_notconnected_dict['pointRadius'] = 4
				local_notconnected_dict['spanGaps'] = 'true'

				for instance in list_of_instances:
					date = instance.date
					connected = instance.connected
					notconnected = instance.notconnected
					index = dict_labels_to_index[date]
					local_connected_dict['data'][index] = connected
					local_notconnected_dict['data'][index] = notconnected

				data['datasets'].append(local_connected_dict)
				data['datasets'].append(local_notconnected_dict)

			responsedata = json.dumps(data)
				#print responsedata
			return JsonResponse({'data': responsedata})

		elif request.POST['type'] == 'reload':
			list_names = []

			for instance in PortModel.objects.all():
				if instance.hostname in list_names:
					continue
				else:
					list_names.append(instance.hostname)

			return JsonResponse({'data': list_names})
			# json_str = '{ labels: ['
			# for label in list_labels:
			# 	json_str += '"' + label + '",'

			# json_str = json_str[:-1]
			# json_str += '], datasets: [' 


# """
# logout view
# """

def logout_view(request):
	logout(request)
	return render(request, 'show/logout_success.html')

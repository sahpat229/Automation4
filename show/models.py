
from django.db import models
import os

# Create your models here.

# class User(models.Model):
# 	username = models.CharField(max_length=200)
# 	password = models.CharField(max_length=2000)
# 	privilege = models.CharField(max_length=100)
# 	def __str__(self):
# 		return self.username

BASE_PATH = os.getcwd()
text_path = BASE_PATH + "/textfiles"
host_path = BASE_PATH + "/hostlists"

"""
TextFiles model, each instance is called a TextFiles,
not a TextFile, unfortunately.  A TextFiles instance describes
the path to a textfile that has commands associated with a OS type
and function type.  Each TextFiles instance has three string fields,
 os, func, and lines.  os refers to the OS of the device, func to the
 function, and lines to the path of the textfile that contains the commands.

 One can initialize a TextFiles instance through:
 	TextFiles(os="OS_NAME", func="FUNC_NAME", lines="PATH_TO_TEXTFILE)
"""

class TextFiles(models.Model):
	os = models.CharField(max_length=200)
	func = models.CharField(max_length=200)
	lines = models.FilePathField(path=text_path)

"""
HostFiles model, each instance is called a HostFiles, not a HostFile,
unfortunately.  A HostFiles instance describes the path to a textfile that
has a list of hosts associated with a OS type and function type.  Each HostFiles
isntance has three string fields, os, func, and lines.  os refers to the OS of the device
category, func to the function, and lines to the path of the textfile that contains a lists
of hosts that match that OS type and Function type.
"""


class HostFiles(models.Model):
	os = models.CharField(max_length=200)
	func = models.CharField(max_length=200)
	lines = models.FilePathField(path=host_path)

"""
NetworkID Model for the subnet locator app
the Model includes networkID, hostname, and interfaces on that host
"""

class NetworkID(models.Model):
	network_ID = models.CharField(max_length=15)
	mask = models.CharField(max_length=15, default="0.0.0.0")
	hostname = models.CharField(max_length=200)
	interface_name = models.CharField(max_length=200)

"""
Automatic Generation Model
the Model includes the fields daily, hour, and minute
Daily identifies whether the model occurs every day
Hour and Minute identify what time the model should run at

Interfaces later with the cron module imported in views.py
"""

class AutomaticGen(models.Model):
	daily = models.BooleanField(default=False)
	hour = models.PositiveIntegerField()
	minute = models.PositiveIntegerField()


"""
Model that has a hostname, date, number of connected, and number of
not connected ports
"""

class PortModel(models.Model):
	hostname = models.CharField(max_length=200)
	date = models.CharField(max_length=200)
	connected = models.IntegerField()
	notconnected = models.IntegerField()
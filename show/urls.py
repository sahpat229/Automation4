from django.conf.urls import patterns, include, url
from django.conf.urls.static import static
from django.contrib import admin
from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from showsite import settings
from django.conf.urls import url

from . import views

#namespace becomes show
app_name = 'show'

"""
url regexes

put more constricted regex above less constricted one
"""

urlpatterns = [
	url(r'list', views.list_options, name='list'),
	url(r'show_(?P<file_name>.+)', views.show_file_show, name='show_file_show'),
	url(r'show', views.show_conf, name='show'),
	url(r'compare_run_(?P<file_name>.+)', views.compare_file_show, name='compare_file_show'),
	url(r'compare_run', views.compare_run, name='compare_run'),
	url(r'logout', views.logout_view, name='logout_view'),
	url(r'push_configs', views.push_configs, name='push_configs'),
	url(r'admin_page', views.admin_page, name='admin_page'),
	url(r'subnet_compare_(?P<file_name>.+)', views.subnet_file_show, name='subnet_file_show'),
	url(r'subnet_compare', views.subnet_compare, name='subnet_compare'),
	url(r'subnet_outputs', views.subnet_outputs, name='subnet_outputs'),
	url(r'topology_mapper', views.topology_mapper, name='topology_mapper'),
	url(r'ports', views.ports, name='ports'),
	#url/ directs to index page
	url(r'^$', views.index, name='index'),

]
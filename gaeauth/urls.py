# -*- coding: utf-8 -*-

try:
	from django.conf.urls import patterns, url # Django 1.6+
except:
	from django.conf.urls.defaults import patterns, url # Django 1.5-

urlpatterns = patterns('',
   url(r'^login/$', 'gaeauth.views.login', name='google_login'),
   url(r'^logout/$', 'gaeauth.views.logout', name='google_logout'),
   url(r'^authenticate/$', 'gaeauth.views.authenticate', name='google_authenticate'),
)

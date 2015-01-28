#///////////////////////////////////////////////////////////////////////////////
#
#  Google Account Backend
#  
#  @source  https://github.com/fhahn/django-gaeauth
#  @fork    https://github.com/Philoozushi/django-gaeauth
#  @diff    Only authorize Django staff and GAE admin users
#           (and don't use settings ALLOWD_USERS or ALLOWED_DOMAINS)
#
#///////////////////////////////////////////////////////////////////////////////

from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.auth.backends import ModelBackend
from google.appengine.api import users


class GoogleAccountBackend(ModelBackend):
	"""
	backend for authentication via Google Accounts on Google
	App Engine
	
	A Django auth.contrib.models.User object is linked to
	a Google Account via the password field, that stores
	the unique Google Account ID
	The Django User object is created the first time a user logs
	in with his Google Account.
	"""
	
	def authenticate(self, user=None, admin=False, **credentials):
		"""Authenticate the given user.
		
		Args:
		  user: The google.appengine.api.users.User object representing the
			  current App Engine user.
		  admin: Whether the current user is an developer/admin of the
			  application.
		"""
		if user is None:
			return None
		
		username, domain = user.email().split('@')
		
		# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
		# Custom (forked) rule :
		# Only authorize Django staff and GAE admin users
		# (changes by Philippe Vignau)
		
		# Case 1) for AppEngine's admins
		if admin:
			
			# try to get Django User, or create one
			django_user, created = User.objects.get_or_create(
				password = user.user_id(),
				defaults = {'email': user.email(), 'username': username}
			)
			
			# if Django User object was just created, or their username/email has changed,
			# or they became AppEngine's admin since the last time they authenticated:
			if django_user.email != user.email()\
				or not django_user.is_active\
				or not django_user.is_staff\
				or not django_user.is_superuser:
				
				# then update their Django User
				django_user.email = user.email()
				django_user.username = username
				django_user.is_active = True
				django_user.is_staff = True
				django_user.is_superuser = True
				django_user.save()
		
		# Case 2) for any other authenticated Google account
		# Rule: they must have an existing Django User account, with staff privilege!
		# -> an authorized Admin must have previously created their account in the admin site.
		else:
			
			# try to get their Django User account
			# 1/ with their AppEngine's User ID, if they already authenticated
			try:
				django_user = User.objects.get(password=user.user_id())
			except:
				# 2/ with their email, for the 1st time they authenticate
				try:
					django_user = User.objects.get(email=user.email())
					django_user.password = user.user_id()
					django_user.save()
				except:
					# No existing Django User = don't authenticate
					return None
			# Existing Django User OK
			# But reject inactive or non staff users
			if not django_user.is_active or not django_user.is_staff:
				return None
			
			# Django Staff User OK
			# if their username/email has changed since the last time they authenticated:
			if django_user.email != user.email():
				django_user.email = user.email()
				django_user.username = username
				django_user.save()
		
		return django_user
		
		# End of forked authentication
		# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
	
	
	def clean_username(self, username):
		return username.split('@')[0]



Django Gaeauth
=======================

An Django authentication backend for using the Google App Engine Users_ and Oauth_ API for user login/logout.

It only works on Google App Engine and you will also need the Djangoappengine backend for Django-Nonrel_.


Fork by Philippe Vignau
~~~~~~~~~~~~~~~~~~~~~~~

**Different rule : only authorize Django staff and GAE admin users**

(and don't use settings ALLOWD_USERS or ALLOWED_DOMAINS)


Installation
====================================

* get the code:

    git clone https://github.com/Philoozushi/django-gaeauth.git
   


* add **gaeauth.backends.GoogleAccountBackend** to your *AUTHENTICATION_BACKENDS* 
  and **gaeauth** to your *INSTALLED_APPS*

  settings.py::

    AUTHENTICATION_BACKENDS = (
          ...
          'gaeauth.backends.GoogleAccountBackend', 
    )

    INSTALLED_APPS = (      
          ...
          'gaeauth',
    )


* include **gaeauth.urls** in your urlconf to **login**, **logout** and **authenticate**
  
  urls.py::
   
    urlpatterns = patterns('',
         ...
         (r'^accounts/', include('gaeauth.urls')),
    )

Now you can use **/accounts/login/** to use Google Accounts for login and **/accounts/logout/** to log out. 


Urls
========

Django-gaeauth provides following named urls:

google_login
  displays the Google login form

google_logout
  logout the user using the Google App Engine Users_ API

google_authenticate
  authenticates the user using the Google App Engine Users_ API


.. _Users: https://code.google.com/appengine/docs/python/users/functions.html
.. _Oauth: https://code.google.com/appengine/docs/python/oauth/functions.html
.. _Djangoappengine: http://www.allbuttonspressed.com/projects/djangoappengine
.. _Django-Nonrel: http://www.allbuttonspressed.com/projects/django-nonrel
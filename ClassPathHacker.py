#!/usr/bin/env python
# encoding: utf-8
"""
@author: kw0ng
@contact: keejiane@gmail.com
@file: ClassPathHacker.py
@time: 2018/3/20 10:10 PM
@desc:
"""

import java.lang.ClassLoader as javaClassLoader
from java.lang import Object as javaObject
from java.io import File as javaFile
from java.net import URL as javaURL
from java.net import URLClassLoader
import jarray


class classPathHacker(object):
	"""Original Author: SG Langer Jan 2007, conversion from Java to Jython
	Updated version (supports Jython 2.5.2) >From http://glasblog.1durch0.de/?p=846

	Purpose: Allow runtime additions of new Class/jars either from
	local files or URL
	"""

	def addFile(self, s):
		"""Purpose: If adding a file/jar call this first
		with s = path_to_jar
		"""
		# make a URL out of 's'
		f = javaFile(s)
		u = f.toURL()
		a = self.addURL(u)
		return a

	def addURL(self, u):
		"""Purpose: Call this with u= URL for
		the new Class/jar to be loaded
		"""
		sysloader = javaClassLoader.getSystemClassLoader()
		sysclass = URLClassLoader
		method = sysclass.getDeclaredMethod("addURL", [javaURL])
		a = method.setAccessible(1)
		jar_a = jarray.array([u], javaObject)
		b = method.invoke(sysloader, [u])
		return u

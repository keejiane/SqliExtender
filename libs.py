#!/usr/bin/env python
# encoding: utf-8
"""
@author: kw0ng
@contact: keejiane@gmail.com
@file: libs.py
@time: 2018/3/9 9:25 PM
@desc:
"""

import os
import random
import string
import re
from settings import PAYLOAD_XML_FILES
from settings import XML_PAYLOADS_PATH
from settings import BOUNDARIES_XML_FILES
from settings import GENERIC_SQL_COMMENT
from settings import ERRORS_XML_FILES
from settings import PAYLOAD_LEVEL
from settings import PAYLOAD_RISK
from settings import BOUNDARY_LEVEL
from settings import SLEEP_TIME_REPLACEMENT
from settings import SLEEP_TIME_MARKER
from settings import JYTHON_STANDALONE_PATH
from xml.etree import ElementTree as ET
from ClassPathHacker import classPathHacker


# 这里存在一个天坑，如果使用xml.etree解析xml本地能正常使用，但是加载到Burpsuite后Jython就会报找不到对应的SAXParser的路径错误
# 原因在于Burpsuite、Jython、SAX加载classpath的方式不一致导致的
# 各种方法尝试过后，找到一个解决方法，使用classPathHacker在java运行的时候更改classpath
# https://support.portswigger.net/customer/portal/questions/17039679-saxparser-dependency-delimma
# https://www.jython.org/jythonbook/en/1.0/appendixB.html#working-with-classpath
# http://python.6.x6.nabble.com/Jython-2-7a2-Issues-with-jarray-and-java-lang-String-Console-prompt-goes-quot-off-quot-td5001336.html
def validate_et(file):
	try:
		# if called from command line with .login CLASSPATH setup right,this works
		doc = ET.parse(file)
	except Exception as e:
		# if called from Apache or account where the .login has not set CLASSPATH
		# need to use run-time CLASSPATH Hacker
		jarLoad = classPathHacker()
		a = jarLoad.addFile("/Users/kwong/SecTools/jython-standalone-2.7.0.jar")
		doc = ET.parse(file)

	return doc


def load_payloads():
	# payloads = []
	for payload_file in PAYLOAD_XML_FILES:
		payload_file = os.path.join(XML_PAYLOADS_PATH, payload_file)

		try:
			doc = validate_et(payload_file)
		except Exception as ex:
			print "something appears to be wrong with the file {}, error as:\n{}.".format(payload_file, ex)

		root = doc.getroot()
		payloads = parse_payload_node(root)
		yield payloads


def load_boundaries():
	boundaries_file = BOUNDARIES_XML_FILES
	try:
		doc = validate_et(boundaries_file)
	except Exception as ex:
		print "something appears to be wrong with the file {}, error as:\n{}.".format(BOUNDARIES_XML_FILES, ex)

	root = doc.getroot()
	return parse_boundaries_node(root)


def load_error():
	errors_file = ERRORS_XML_FILES
	try:
		doc = validate_et(errors_file)
	except Exception as ex:
		print "something appears to be wrong with the file {}, error as:\n{}.".format(ERRORS_XML_FILES, ex)

	root = doc.getroot()
	return parse_errors_node(root)


def parse_payload_node(node):
	tests = []
	for element in node.getiterator("test"):
		test = {}

		for child in element.getchildren():
			if child.text and child.text.strip():
				test[child.tag] = child.text
			else:
				if len(child.getchildren()) == 0:
					test[child.tag] = None
					continue
				else:
					test[child.tag] = {}

				for gchild in child.getchildren():
					if gchild.tag in test[child.tag]:
						prevtext = test[child.tag][gchild.tag]
						test[child.tag][gchild.tag] = [prevtext, gchild.text]
					else:
						test[child.tag][gchild.tag] = gchild.text
						# yield test
		tests.append(test)
	return tests


def parse_boundaries_node(node):
	# boundaries = []
	for element in node.getiterator("boundary"):
		boundary = {}
		for child in element.getchildren():
			if child.text:
				boundary[child.tag] = child.text
			else:
				boundary[child.tag] = None

		yield boundary
		# boundaries.append(boundary)
	# return boundaries


def parse_errors_node(node):
	errors = {}
	for element in node.getiterator("dbms"):
		dbms = element.get('value')
		errors[dbms] = []
		for child in element.getchildren():
			regex = child.get("regexp")
			errors[dbms].append(regex)

	return errors


def random_str(size=4, chars=string.ascii_uppercase):
	return ''.join(random.choice(chars) for _ in xrange(size))


def random_num(size=4, chars=string.digits):
	return int(''.join(random.choice(chars) for _ in xrange(size)))


def random_diff_str(size=4):
	s1 = random_str(size)
	s2 = random_str(size)
	if s1 != s2:
		return s1, s2
	else:
		random_diff_str(size=4)


def random_diff_num(size=4):
	n1 = random_num(size)
	n2 = random_num(size)
	if n1 != n2:
		return n1, n2
	else:
		random_diff_str(size=4)


def get_filtered_content(page, only_text=True, split=''):
	"""
	:param page: http response
	:param only_text: 是否只保留文本
	:param split: 标签替换符
	:return: http response
	"""
	ret_val = page
	if isinstance(page, basestring):
		ret_val = re.sub(r"(?si)<script.+?</script>|<!--.+?-->|<style.+?</style>%s" % (r"|<[^>]+>|\t|\n|\r" if only_text else ""), split, page)
		ret_val = re.sub(r"%s{2,}" % split, split, ret_val)
		ret_val = html_unescape(ret_val.strip().strip(split))

	return ret_val


def html_unescape(value):
	ret_val = value
	if value and isinstance(value, basestring):
		# six.string_types
		codes = (("&lt;", '<'), ("&gt;", '>'), ("&quot;", '"'), ("&nbsp;", ' '), ("&amp;", '&'), ("&apos;", "'"))
		ret_val = reduce(lambda x, y: x.replace(y[0], y[1]), codes, ret_val)
		try:
			ret_val = re.sub(r"&#x([^ ;]+);", lambda match: unichr(int(match.group(1), 16)), ret_val)
		except ValueError:
			pass
	return ret_val


def grep_error(page):
	regex = load_error()
	# regex = errors_regex
	if regex and page:
		for db_name in regex.keys():
			for r_str in regex[db_name]:
				matched_str = re.search(r'%s' % r_str, page, re.DOTALL | re.IGNORECASE)
				if matched_str:
					return db_name, matched_str

	return None, None


def parse_tag(tag):
	if not tag.isdigit():
		if '-' in tag:
			tag = [str(x) for x in xrange(int(tag.split('-')[0]), int(tag.split('-')[1])+1)]
		elif ',' in tag:
			tag = tag.split(',')
		else:
			tag = [tag]

	return tag


def payload_replace(payload):
	if payload is None:
		return

	rc = re.findall(r'(?i)\[GENERIC_SQL_COMMENT\]', payload)
	# print rn, rs, rc
	if len(rc) and set(rc):
		for _ in rc:
			payload = payload.replace(_, GENERIC_SQL_COMMENT)
	rn = re.findall(r'(?i)\[RANDNUM(?:\d+)?\]', payload)
	if len(rn) and set(rn):
		for _ in rn:
			payload = payload.replace(_, str(random_num()))
	rs = re.findall(r'(?i)\[RANDSTR(?:\d+)?\]', payload)
	if len(rs) and set(rs):
		for _ in rs:
			payload = payload.replace(_, random_str())

	def replace_time(rtype, payload):
		if rtype == 'sleep':
			payload = payload.replace(SLEEP_TIME_MARKER, str(SLEEP_TIME_REPLACEMENT))
		if rtype == 'delay':
			pass
		return payload

	if SLEEP_TIME_MARKER in payload:
		payload = replace_time('sleep', payload)

	if '[DELAY]' in payload:
		payload = replace_time('delay', payload)

	if '[ORIGVALUE]' in payload:
		payload = payload.replace('[ORIGVALUE]', '1234')
	if '[ORIGINAL]' in payload:
		payload = payload.replace('[ORIGINAL]', '2345')

	return payload


def gen_payloads(p, boundaries):
	"""
	:param p: 单独的一条payload
	:param boundaries: 所有的boundary
	:return: Mixed, boolean_based=>tuple(iterators), others=>string(iterator)
	"""
	# merge_payload = None
	# boundaries = load_boundaries()
	# print p['level'], p['risk']
	if int(p['level']) <= PAYLOAD_LEVEL and int(p['risk']) <= PAYLOAD_RISK:
		for b in boundaries:
			if int(b['level']) <= BOUNDARY_LEVEL:
				clause_match = False
				for c in parse_tag(p['clause']):
					if c in parse_tag(b['clause']):
						clause_match = True
						break

				if p['clause'] != [0] and b['clause'] != [0] and not clause_match:
					continue

				where_match = False
				for w in parse_tag(p['where']):
					if w in parse_tag(b['where']):
						where_match = True
						break

				if not where_match:
					continue

				prefix = '' if not b['prefix'] else b['prefix']
				suffix = '' if not b['suffix'] else b['suffix']
				if 'comment' in p['request']:
					suffix = p['request']['comment']
				payload = '' if not p['request']['payload'] else p['request']['payload']

				try:
					if int(p['stype']) == 1:
						cmp_payload = '' if not p['response']['comparison'] else p['response']['comparison']
						true_payload = prefix + ' ' + payload + suffix
						false_payload = prefix + ' ' + cmp_payload + suffix
						# false_payload = payload_replace(false_payload)
						# true_payload = payload_replace(true_payload)
						merge_payload = (true_payload, false_payload)

					elif int(p['stype']) == 5:
						time_payload = prefix + ' ' + payload + suffix
						merge_payload = time_payload

					elif int(p['stype']) == 4:
						stack_payload = prefix + ' ' + payload + suffix
						merge_payload = stack_payload
					else:
						break
				except Exception as e:
					print '***error in merge or replace payload: '+p['request']['payload']+'\n%s' % e.message
					continue

				yield merge_payload


if __name__ == '__main__':
	payloads = load_payloads()
	boundaries = load_boundaries()
	for xml in payloads:
		for x in xml:
			for p in gen_payloads(x, boundaries):
				print p

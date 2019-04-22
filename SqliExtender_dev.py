#!/usr/bin/env python
# encoding: utf-8
"""
@author: kw0ng
@contact: keejiane@gmail.com
@file: SqliExtender_dev.py
@time: 2018/3/8 10:34 PM
@desc:
"""

from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from array import array
from difflib import SequenceMatcher
from settings import GREP_STRING
from settings import MAX_RATIO
from settings import MIN_DIFF_LEN
from settings import SLEEP_TIME_MARKER
from settings import SLEEP_TIME_REPLACEMENT
from libs import gen_payloads
from libs import grep_error
from libs import get_filtered_content
from libs import payload_replace
from libs import load_payloads
from libs import load_boundaries
import re
import time


class BurpExtender(IBurpExtender, IScannerCheck):
	# implement IBurpExtender
	def __init__(self):
		self.ext_name = 'sqliExtender'

	def registerExtenderCallbacks(self, callbacks):
		# keep a reference to our callbacks object
		self._callbacks = callbacks

		# obtain an extension helpers object
		self._helpers = callbacks.getHelpers()

		# set our extension name
		callbacks.setExtensionName(self.ext_name)

		# register ourselves as a custom scanner check
		callbacks.registerScannerCheck(self)
		# callbacks.registerScannerInsertionPointProvider(self)
		print "Auther: Kw0ng"

	# helper method to search a response for occurrences of a literal match string
	# and return a list of start/end offsets

	def _get_matches(self, response, match):
		matches = []
		start = 0
		res_len = len(response)
		match_len = len(match)
		while start < res_len:
			start = self._helpers.indexOf(response, match, True, start, res_len)
			if start == -1:
				break
			matches.append(array('i', [start, start + match_len]))
			start += match_len

		return matches

	# implement IScannerCheck
	def doPassiveScan(self, baseRequestResponse):
		# look for matches of our passive check grep string
		matches = self._get_matches(baseRequestResponse.getResponse(), self._helpers.stringToBytes(GREP_STRING))
		if len(matches) == 0:
			return None

		# report the issue
		return [CustomScanIssue(
			baseRequestResponse.getHttpService(),
			self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
			[self._callbacks.applyMarkers(baseRequestResponse, None, matches)],
			"CMS Info Leakage",
			"The response contains the string: " + GREP_STRING,
			"Information")]

	def doActiveScan(self, baseRequestResponse, insertionPoint):
		# 存在两个分支判断报错注入
		def error_return(response, highlights, error_payload):
			matches_offset = self._get_matches(response.getResponse(), self._helpers.stringToBytes(highlights))
			req_highlights = [insertionPoint.getPayloadOffsets(error_payload)]
			# report the issue
			return [CustomScanIssue(
				baseRequestResponse.getHttpService(),
				self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
				[self._callbacks.applyMarkers(response, req_highlights, matches_offset)],
				"error-based SQL injection",
				"A error-based SQL injection was detected: " + highlights,
				"High")]

		payloads = load_payloads()
		boundaries = load_boundaries()
		boolean_blind_injectable = error_injectable = time_injectable = False
		# 添加payload有三种方式：1、直接在参数值后面添加；2、将参数值替换为一个整数；3、将参数值删除直接添加payload
		# 测试空链接
		# 跳转的情况
		# is_res_stable = self.isResStable(baseRequestResponse)

		# if is_res_stable:
		for xml in payloads:
			for payload in xml:
				ratio = 0
				# union注入只判断order by语句，放在boolean注入的payload中
				# inline注入同报错注入，只判断boundaries前缀能否爆出错误信息
				if int(payload['stype']) == 1:
					for true_payload, false_payload in gen_payloads(payload, boundaries):
						# burpsuite默认将payload直接添加在参数等号后面
						true_payload = insertionPoint.getBaseValue() + true_payload
						false_payload = insertionPoint.getBaseValue() + false_payload
						# 使用HEAD方式请求content-length判断布尔注入以节省带宽，暂未实现
						check_null_connection = self.checkNullConnection()
						if check_null_connection:
							true_res_cnt = self.nullQuery(true_payload)
							false_res_cnt = self.nullQuery(false_payload)
							if abs(true_res_cnt - false_res_cnt) > MIN_DIFF_LEN - 5:
								boolean_blind_injectable = True

						else:
							true_res_cnt = self.makeCheckRequest(baseRequestResponse, insertionPoint, true_payload)
							true_res_cnt_str = self._helpers.bytesToString(true_res_cnt.getResponse())
							false_res_cnt = self.makeCheckRequest(baseRequestResponse, insertionPoint, false_payload)
							false_res_cnt_str = self._helpers.bytesToString(false_res_cnt.getResponse())

							# 判断返回是否存在报错信息，如存在即认为是报错注入
							error_dbms, error_matched = grep_error(true_res_cnt_str)
							if error_dbms and error_matched:
								error_greped = error_matched.group()
								error_injectable = True

								if error_injectable:
									# pass
									return error_return(true_res_cnt, error_greped, true_payload)

							ratio = self.getRatio(true_res_cnt_str, false_res_cnt_str)
							# 302跳转容易导致ratio小于0.98，处理302跳转
							if ratio < MAX_RATIO:
								# 可以将heavily dynamic判断放这里
								if self.isResStable(baseRequestResponse):
									boolean_blind_injectable = True
								else:
									# if ratio <= MAX_RATIO: heavily dynamic
									# 从boundaries中取prefix作为payload
									# 请求不稳定就只检测报错注入
									for boundary in boundaries:
										boundary_prefix = boundary['prefix']
										error_check = self.makeCheckRequest(baseRequestResponse, insertionPoint,
										                                    boundary_prefix)
										error_check_response = self._helpers.bytesToString(error_check.getResponse())
										error_dbms, error_matched = grep_error(error_check_response)
										if error_dbms and error_matched:
											error_injectable = True

										if error_injectable:
											# report the issue
											return error_return(error_check, error_matched, boundary_prefix)
									# 还可以检测延时注入
							else:
								# if len(candidate) > MIN_DIFF_LEN
								# injectable = True
								# 如果ratio大于0.98，但两次返回内容去重后存在一个大于MIN_DIFF_LEN的字段，则仍然认为存在布尔盲注
								original = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(),
								                                           baseRequestResponse.getRequest())
								original_res_cnt_str = self._helpers.bytesToString(original.getResponse())
								original_set = set(
									get_filtered_content(original_res_cnt_str, True, '\n').split('\n'))
								true_set = set(
									get_filtered_content(true_res_cnt_str, True, '\n').split('\n'))
								false_set = set(
									get_filtered_content(false_res_cnt_str, True, '\n').split('\n'))
								if original_set == true_set != false_set:
									candidates = true_set - false_set
									if candidates:
										candidates = sorted(candidates, key=lambda _: len(_))
										for c in candidates:
											if re.match(r"\A[\w.,! ]+\Z", c) and ' ' in c and c.strip() and len(c) > MIN_DIFF_LEN:
												print 'candidate invoked!'
												boolean_blind_injectable = True
												# ratio = len(c)

						if boolean_blind_injectable:
							req_highlights1 = [insertionPoint.getPayloadOffsets(true_payload)]
							req_highlights2 = [insertionPoint.getPayloadOffsets(false_payload)]
							if check_null_connection:
								res_variations = self._helpers.analyzeResponseVariations(true_res_cnt, false_res_cnt)
								res_variations_lst = res_variations.getVariantAttributes()
								res_highlights1 = [self._get_matches(true_res_cnt, self._helpers.stringToBytes(_))
								                   for _ in res_variations_lst]
								res_highlights2 = [self._get_matches(false_res_cnt, self._helpers.stringToBytes(_))
								                   for _ in res_variations_lst]
							else:
								res_highlights1 = res_highlights2 = None
							# report the issue
							return [CustomScanIssue(
								baseRequestResponse.getHttpService(),
								self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
								[self._callbacks.applyMarkers(true_res_cnt, req_highlights1, res_highlights1),
								 self._callbacks.applyMarkers(false_res_cnt, req_highlights2, res_highlights2)],
								"boolean-based blind injection",
								"Different length of response were detected: %s(ratio)." % str(ratio),
								"High")]

				# stacked_query注入判断方式同时间注入，都是判断返回时长
				elif int(payload['stype']) == 5 or int(payload['stype']) == 4:
					def calculate_seconds(start):
						return time.time() - start
					for true_payload in gen_payloads(payload, boundaries):
						# 99.9999999997440% of all non time-based SQL injection affected
						# response times should be inside +-7*stdev([normal response times]
						# sqlmap中stdev函数需要多个（>=2）返回时长作为参数, 暂不实现
						# burpsuite默认将payload直接添加在参数等号后面
						time_payload = true_payload = insertionPoint.getBaseValue()+true_payload
						start_time1 = time.time()
						true_res_cnt = self.makeCheckRequest(baseRequestResponse, insertionPoint, time_payload)
						if true_res_cnt:
							response_time1 = calculate_seconds(start_time1)
							if SLEEP_TIME_MARKER in true_payload and response_time1 > SLEEP_TIME_REPLACEMENT - 0.5:
								time_payload = time_payload.replace(SLEEP_TIME_MARKER, '0')
								start_time2 = time.time()
								false_res_cnt = self.makeCheckRequest(baseRequestResponse, insertionPoint, time_payload)
								response_time2 = calculate_seconds(start_time2)
								if false_res_cnt and response_time2 < 0.5:
									# time_injectable = True
									# 再请求一次true，确认漏洞存在
									start_time3 = time.time()
									true_res_cnt = self.makeCheckRequest(baseRequestResponse, insertionPoint, true_payload)
									response_time3 = calculate_seconds(start_time3)
									if true_res_cnt and response_time3 > SLEEP_TIME_REPLACEMENT - 0.5:
										time_injectable = True

						if time_injectable:
							true_payload = payload_replace(true_payload)
							# false_payload = false_payload.replace(SLEEP_TIME_MARKER, '0')
							req_highlights = [insertionPoint.getPayloadOffsets(true_payload)]
							# req_highlights2 = [insertionPoint.getPayloadOffsets(false_payload)]
							return [CustomScanIssue(
								baseRequestResponse.getHttpService(),
								self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
								[self._callbacks.applyMarkers(true_res_cnt, req_highlights, None)],
								"time-based blind injection",
								"Delayed response was detected: %s(s)." % str(response_time3),
								"High")]

				else:
					print 'Unsupport stype in payload:%s' % payload

	def checkNullConnection(self):
		return False

	def nullQuery(self):
		return None

	def getRatio(self, text1, text2):
		# seq_matcher = SequenceMatcher(lambda x: x in ' ')
		seq_matcher = SequenceMatcher(None)
		seq_matcher.set_seqs(text1, text2)
		# seq_matcher.set_seq1(text2)
		ratio = seq_matcher.quick_ratio()

		return ratio

	def makeCheckRequest(self, baseRequestResponse, insertionPoint, payload):
		payload = payload_replace(payload)
		print payload
		check_request = insertionPoint.buildRequest(payload)
		check_response = self._callbacks.makeHttpRequest(
			baseRequestResponse.getHttpService(), check_request)

		return check_response

	def comparedCntLength(self, baseRequestResponse, insertionPoint, payload):
		check_req_res = self.makeCheckRequest(baseRequestResponse, insertionPoint, payload)
		res_headers = self._helpers.analyzeResponse(check_req_res.getResponse()).getHeaders()
		cnt_length = self.headersToDict(res_headers)['CONTENT-LENGTH']

		return cnt_length

	def getCntLength(self, baseRequestResponse):
		response = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(),
		                                           baseRequestResponse.getRequest())
		res_readers = self._helpers.analyzeResponse(response.getResponse()).getHeaders()
		cnt_length = self.headersToDict(res_readers)['CONTENT-LENGTH']
		return cnt_length

	def headersToDict(self, rawHeaders):
		headers = dict((header.split(': ')[0].upper(), header.split(': ', 1)[1]) for header in rawHeaders[1:])
		return headers

	def isResStable(self, baseRequestResponse):
		# Burpsuite每个insertpoint都会调用doActiveScan方法，isResStable放在里面判断稳定性会多发大量空包，暂时移除
		cent_lengths = []
		for i in xrange(3):
			cnt_length = self.getCntLength(baseRequestResponse)
			cent_lengths.append(cnt_length)

		if len(set(cent_lengths)) == 1:
			return True
		else:
			return False

	def getRedirectResponse(self):
		# 处理跳转请求
		# self._helper.buildHttpMassage(Request/Service)
		pass

	def consolidateDuplicateIssues(self, existingIssue, newIssue):
		# This method is called when multiple issues are reported for the same URL
		# path by the same extension-provided check. The value we return from this
		# method determines how/whether Burp consolidates the multiple issues
		# to prevent duplication
		#
		# Since the issue name is sufficient to identify our issues as different,
		# if both issues have the same name, only report the existing issue
		# otherwise report both issues
		if existingIssue.getIssueName() == newIssue.getIssueName():
			return -1

		return 0


#
# class implementing IScanIssue to hold our custom scan issue details
#
class CustomScanIssue(IScanIssue):
	def __init__(self, httpService, url, httpMessages, name, detail, severity):
		self._httpService = httpService
		self._url = url
		self._httpMessages = httpMessages
		self._name = name
		self._detail = detail
		self._severity = severity

	def getUrl(self):
		return self._url

	def getIssueName(self):
		return self._name

	def getIssueType(self):
		return 0

	def getSeverity(self):
		return self._severity

	def getConfidence(self):
		return "Certain"

	def getIssueBackground(self):
		pass

	def getRemediationBackground(self):
		pass

	def getIssueDetail(self):
		return self._detail

	def getRemediationDetail(self):
		pass

	def getHttpMessages(self):
		return self._httpMessages

	def getHttpService(self):
		return self._httpService

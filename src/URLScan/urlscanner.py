'''
Created on May 22, 2012

@author: Kelvin Lomboy
@version: v0.1
@summary: A class module to connect to URL scan services and parse
          results.
@contact: kelvin@kelvinlomboy.com
@requires: Python 2.7.2+, requests and bs4 modules

'''

import re
import sys
from cStringIO import StringIO

import requests
from bs4 import BeautifulSoup

#------------#
# Main Class #
#------------#


class URLScanner():
    '''This class, when instantiated, will connect to the specified
    URL scan service and return its content. Certain URL data are
    parsed depending on the service, including scan results returned
    by different antivirus engines.

    '''

    def __init__(self, url, service, proxy=None):
        '''Constructor.

        This method sets initial variables. Then it will connect to
        the specified URL scan website and initiate a scan. The content
        result is return when the scan is completed for which certain
        data including all scanning results are parsed.

        '''

        #---------------#
        # Set Variables #
        #---------------#

        self.url = url
        service = service
        self.proxy = {"http":proxy}
        self.host = URLScanner.parse_url_to_host(self.url)
        self.params = {'url': self.host, 'go': 'Scan+Now'}

        #-----------------------#
        # URL Scanning Services #
        #-----------------------#

        #---urlvoid---
        if service == "urlvoid":
            self.url_service = "http://urlvoid.com/scan/"

        #---ipvoid---
        elif service == "ipvoid":
            self.url_service = "http://ipvoid.com/scan/"

        #--------------------#
        # Service Connection #
        #--------------------#

        #---connect and scan host---
        try:
            r = requests.post(self.url_service +
                               self.host, data=self.params, proxies=self.proxy)
            self.contents = BeautifulSoup(r.content)
        except:
            raise ConnectionError("Network Error: can not connect")

        #------------------------#
        # Parse Scanning Results #
        #------------------------#

        #---urlvoid results---
        try:
            if service == "urlvoid":
                self.domain = self.host
                self.ip = self.contents.find("td", text="IP Address:")\
                .find_next().get_text().split()[0]
                self.isp = self.contents.find("td", text="ISP:")\
                .find_next().get_text()
                self.country = self.contents.find("td", text="IP Country:")\
                .find_next().get_text().strip()
                self.created = self.contents.find("td", text="Domain Created:")\
                .find_next().get_text()
                self.alerts = URLScanner.get_alert(self.contents)
                self.result = True
        except:
            self.domain = self.host
            self.ip = "Unknown"
            self.isp = "Unknown"
            self.country = "Unknown"
            self.created = "Unknown"
            self.alerts = [], []
            self.result = False

        #---ipvoid results---
        if service == "ipvoid":
            self.ip = self.host
            self.isp = self.contents.find("td", text="ISP:")\
            .find_next().get_text()
            self.hostname = self.contents.find("td", text="IP Hostname:")\
            .find_next().get_text()
            self.country = self.contents.find("td", text="IP Country:")\
            .find_next().get_text().strip()
            self.alerts = URLScanner.get_alert(self.contents)

    #---------------#
    # Class Methods #
    #---------------#

    @classmethod
    def check_host(cls, host):
        '''Check whether host is a hostname or ip address.'''

        valid_ip = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]\
        )\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
        valid_name = "^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9\
        ])(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]))*$"

        if re.match(valid_ip, host):
            return "ip"
        elif re.match(valid_name, host):
            return "hostname"
        else:
            None

    @classmethod
    def parse_url_to_host(cls, url):
        ''' Parse URL and extracts host's name or ip address.'''

        if ("http://") or ("https://") in url:
            if "http://" in url:
                protocol = "http://"
            else:
                protocol = "https://"
            host = url.strip().split(protocol).pop().split("/")\
            .pop(0).split(":").pop(0)
        else:
            host = url.strip().split("/").pop(0).split(":").pop(0)
        return host

    @classmethod
    def get_alert(cls, contents):
        '''Retrieves scan results for a URL.'''

        links = []
        alerts = []

        #------------------#
        # URLVoid & IPVoid #
        #------------------#

        # URLVoid and IPVoid scan results are located in the tablesorter table.
        # The av engine names are parsed as well as their results and links
        # which then are appended to their respective list and returned by this
        # function.
        tr_tags = contents.find("table", "tablesorter").find_all("tr")
        for tr in tr_tags:
            if tr.td:
                output = StringIO()
                engine = str(tr.td.get_text())
                print >>output, engine
                for td_tag in tr.td.find_next_siblings():
                    print >>output, td_tag.get_text().strip()
                    if td_tag.a:
                        link = td_tag.a.get('href')
                        links.append(link)
                        print >>output, link

                alerts.append(output.getvalue())
                output.close()

        return alerts, links

#-------------------#
# Exception Classes #
#-------------------#


#---reserved---
class SomethingBlewUp(BaseException):
    pass


#---for raising connection error---
class ConnectionError(BaseException):
    pass

#----------------#
# Module Warning #
#----------------#

if __name__ == '__main__':
    print "* import this as a module *"

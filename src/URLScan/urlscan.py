'''
Created on May 22, 2012

@author: Kelvin Lomboy
@version: v0.1
@summary: A tool for detecting malicious URL
@contact: kelvin@kelvinlomboy.com

'''

import sys
import time
import webbrowser
import argparse

from urlscanner import *

#-----------#
# Functions #
#-----------#


def display_title():
    '''Display program title.'''

    print '''
 _   _ ____  _                         
| | | |  _ \| |    ___  ___ __ _ _ __  
| | | | |_) | |   / __|/ __/ _` | '_ \ 
| |_| |  _ <| |___\__ \ (_| (_| | | | |
 \___/|_| \_\_____|___/\___\__,_|_| |_|
                                    v0.1

      A tool for detecting malicious URL
     Powered by URLVoid.com & IPVoid.com
                        by Kelvin Lomboy
    '''


def controller():
    '''Runs script and handles command line options.'''

    desc = "A tool for detecting malicious URL"

    parser = argparse.ArgumentParser(description=desc,
                                     prog=display_title(),
                                     version='%(prog)s v0.1')

    parser.add_argument('-f', '--file',
                        help='file with URLs to scan',
                        action='store')

    parser.add_argument('-p', '--proxy',
                        help='set proxy, ex. 127.0.0.1:8081',
                        action='store',
                        default=None)

    parser.add_argument('-t', '--tab',
                        help='open links in new browser tab',
                        action='store_true',
                        default=False)

    parser.add_argument('url',
                        help='URL to scan',
                        nargs='?',
                        action='store')

    args = parser.parse_args()
    url = args.url
    file_ = args.file
    proxy = args.proxy
    tab = args.tab

    if not (url or file_):
        parser.error("no URL or file supplied")
    #---URL--
    if url:
        urls = ([url])
    #---file---
    else:
        try:
            with open(file_) as f:
                urls = f.readlines()
        except IOError:
            print "[!] could not open file or file does not exist"
            sys.exit(1)

    return proxy, tab, urls


def print_alert(scanner, tab):
    '''Print only detected scan results.
    If the -t option is used, open new browser
    tabs for each link provided.

    '''
    i = 0
    detected = 0
    tab_links = []

    alerts, links = scanner.alerts
    for alert in alerts:
        if "DETECTED" in alert:
            tab_links.append(links[i])
            print alert
            detected += 1
        i += 1

    if not detected:
        print "Nothing found.\n"

    print "Total: " + str(detected) + "\r"

    if detected == 0:
        print "Verdict: Not detected"
    elif detected == 1:
        print "Verdict: Suspicious"
    elif detected == 2:
        print "Verdict: Highly Suspicious"
    elif detected >= 3:
        print "Verdict: Malicious"
    print_dotted_lines()

    if tab and tab_links:
        sys.stdout.write("\nOpening links in browser...\r")
        sys.stdout.flush()
        time.sleep(5)
        sys.stdout.write(" " * 30)

        for link in tab_links:
            webbrowser.open(link, new=2)


def print_dotted_lines():
    '''Print dotted lines to output.'''

    print "----------------------------------------"


def main():
    '''The main function.

    Parses user's options and creates URLscanner
    objects depending on the type of URL. The creation
    of the objects initiates a scan using IPVoid or
    URLvoid services and some data, along with the
    results for each URL, are extracted and printed to
    the screen.

    '''
    proxy, tab, urls = controller()
    sys.stdout.write("Scanning, please wait...\r")
    sys.stdout.flush()

    for url in urls:
        #---get hostname or ip address and strip out the rest---
        host = URLScanner.parse_url_to_host(url)

        # Checks whether hostname or ip. Depending on the results,
        # the appropriate URL scanner object is instantiated.
        if URLScanner.check_host(host) == "ip":
            try:
                ipvoid = URLScanner(url, service="ipvoid", proxy=proxy)
                print "IP:       " + ipvoid.ip + " " * 15
                print "ISP:      " + ipvoid.isp
                print "Hostname: " + ipvoid.hostname
                print "Country:  " + ipvoid.country
                print
                print_alert(ipvoid, tab)
            except ConnectionError:
                print "[!] could not connect to IPVoid"
                print_dotted_lines()

        elif URLScanner.check_host(host) == "hostname":
            try:
                urlvoid = URLScanner(url, service="urlvoid", proxy=proxy)
                print "Domain:   " + urlvoid.domain + " " * 15
                print "IP:       " + urlvoid.ip
                print "ISP:      " + urlvoid.isp
                print "Country:  " + urlvoid.country
                print "Created:  " + urlvoid.created
                print
                print_alert(urlvoid, tab)
            except ConnectionError:
                print "[!] could not connect to URLVoid"
                print_dotted_lines()

        else:
            print "Host: " + host + " " * 15
            print "[!] invalid host"
            print "[!] scan skipped"
            print_dotted_lines()

#------#
# Main #
#------#

if __name__ == '__main__':
    #---script starts here---
    main()

# -*- coding: utf-8 -*-
# 分析nmap的xml格式输出，检测主机是否受phoenix talon
# phoenix talon: kernel 2.5.69 - 4.11
# nmap -v -A -Pn -iL iplist.txt -oX output.xml
# python parse.py output.xml
# 输出有三种情况 Y是确认受影响，P是有可能受影响，N是不受影响

import xml.dom.minidom as xml
import sys
import re

def parse(fileName):
    d = xml.parse(fileName)
    for hostElement in d.getElementsByTagName('host'):
        ipAddr = hostElement.getElementsByTagName('address')[0].getAttributeNode('addr').value

        result = 'N'
        for e in hostElement.getElementsByTagName('osclass'):
            #print e.getAttributeNode('accuracy').value,
            #print e.getAttributeNode('vendor').value,
            #print e.getAttributeNode('osfamily').value
            if len(e.getElementsByTagName('cpe')) > 0:
                cpe = e.getElementsByTagName('cpe')[0]
                #print cpe.firstChild.nodeValue
                kernel = re.findall('linux_kernel:(\d)(?:\.(\d+))?(?:\.(\d+))?', cpe.firstChild.nodeValue)
                if not kernel:
                    continue
                kernel = kernel[0]
                #print kernel
                if kernel[2]:
                    # 2.5.69 - 4.11.0
                    low = 20569
                    high = 41100
                elif kernel[1]:
                    low = 20500
                    high = 41100
                else:
                    low = 20000
                    high = 40000
                try:
                    major = int(kernel[0])
                except:
                    major = 0
                try:
                    minor = int(kernel[1])
                except:
                    minor = 0
                try:
                    rev = int(kernel[2])
                except:
                    rev = 0

                #print major,minor,rev
                v = major * 10000 + minor * 100 + rev
                #print v
                if low < v < high:
                    if e.getAttributeNode('accuracy').value == '100':
                        result = 'Y'
                        break
                    else:
                        result = 'P'
        print ipAddr, result

if __name__ == '__main__':
    parse(sys.argv[1])



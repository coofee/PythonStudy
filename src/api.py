#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import sys
import requests


def get(url, headers):
    originResp = requests.get(url=url, headers=headers)
    originText = originResp.text
    originResp.close()
    print(f"Origin Resp:\n {originText}")

    for key in headers.copy():
        value = headers[key]
        if "user-agent" == key.lower():
            print(f"skip header User-Agent={value}")
            continue

        print(f"remove key={key}, value={value}")
        headers.pop(key)
        resp = requests.get(url=url, headers=headers)
        currentText = resp.text
        if originText != currentText:
            print(f"Diff Resp:\n {currentText}")
            print(f"resp different from origin until {key}={value}")
            break
        else:
            print(f"resp is same to origin.")      

class ApiConfig():

    def __init__(self, url, headers):
        self.url = url
        self.headers = headers

def read(configFilePath):
    """
    config file 每行是一个key value键值对，其中Url对应请求的地址，剩余则全部为header:
    Url: http://xxx/xxx/xxx
    Accept-Encoding: gzip,deflate
    """

    url = ""
    headers = {}
    index = 0
    with open(configFilePath, "r") as reader:
        for line in reader:
            line = line.strip()
            index += 1
            print(f"#{index}: line={line}")
            if len(line) > 1:
                splitIndex = line.index(':')
                if splitIndex > 1:
                    key = line[:splitIndex].strip()
                    value = line[splitIndex + 1 :].strip()
                    if "url" == key.lower():
                        url = value
                    else:
                        headers[key] = value

    print(f"url={url}, headers={headers}")
    return ApiConfig(url, headers)


if __name__ == "__main__":
    argvLen = len(sys.argv)
    if (argvLen < 2):
        print(f"usage: python api.py [path/to/api/config/file]")
    configFile = sys.argv[1]
    apiConfig = read(configFile)    
    get(apiConfig.url, apiConfig.headers)
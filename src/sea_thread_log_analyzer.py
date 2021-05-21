#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

# java.util.Timer.
# java.util.concurrent.
# EO.execute(PG:20)

# 05-17 20:37:17.562 24718 24718 D jvmti_sea: MethodEntry; main thread@0x81 start thread@0x43
# 05-17 20:37:17.562 24718 24718 D jvmti_sea: printThreadStackTrace; name=main, stack trace depth=5, Exception Stack Trace
# 05-17 20:37:17.562 24718 24718 D jvmti_sea: 	at java.lang.Thread.start(Thread.java:877)
# 05-17 20:37:17.562 24718 24718 D jvmti_sea: 	at android.app.SharedPreferencesImpl.startLoadFromDisk(SharedPreferencesImpl.java:121)
# 05-17 20:37:17.562 24718 24718 D jvmti_sea: 	at android.app.SharedPreferencesImpl.<init>(SharedPreferencesImpl.java:109)
# 05-17 20:37:17.562 24718 24718 D jvmti_sea: 	at android.app.ContextImpl.getSharedPreferences(ContextImpl.java:476)
# 05-17 20:37:17.562 24718 24718 D jvmti_sea: 	at android.app.ContextImpl.getSharedPreferences(ContextImpl.java:452)
# 05-17 20:37:17.562 24718 24768 D jvmti_sea: ThreadStart; activeThreadCount=1, name=SharedPreferencesImpl-load, priority=5, is_daemon=0
# 05-17 20:37:17.565 24718 24768 D jvmti_sea: ThreadEnd; activeThreadCount=0, name=SharedPreferencesImpl-load, priority=5, is_daemon=0

import json
import sys
import os

TAG_THREAD_STACK_TRACE = 'jvmti_sea: printThreadStackTrace'

TAG_THREAD_STACK_TRACE_DEPTH = ', stack trace depth='
TAG_THREAD_STACK_TRACE_DEPTH_LEN = len(TAG_THREAD_STACK_TRACE_DEPTH)

TAG_THREAD_TRACE_TRACE_ELEMENT = 'jvmti_sea: 	at ';
TAG_THREAD_TRACE_TRACE_ELEMENT_LEN = len(TAG_THREAD_TRACE_TRACE_ELEMENT)

TAG_THREAD_START = 'jvmti_sea: ThreadStart'
TAG_THREAD_END = 'jvmti_sea: ThreadEnd'

TAG_NAME = ', name='
TAG_NAME_LEN = len(TAG_NAME)

THREAD_MODULES = {
    'unknown': {
        'name': '未知',
        'key': 'unknown'
    },
    'shared_preferences': {
        'name': 'shared_preferences',
        'key': 'shared_preferences',
        'threadNames': [
            'SharedPreferencesImpl-load'
        ],
        'packages': [
            'android.app.SharedPreferencesImpl.'
        ],
    },
    'bugly': {
        'name': 'bugly',
        'key': 'bugly',
        'threadNamePrefix': 'Bugly',
        'packages': [
            'com.tencent.bugly.'
        ]
    },
    'okhttp3': {
        'name': "okhttp3",
        'key': 'okhttp3',
        'threadNamePrefix': 'OkHttp',
        'packages': [
            'okhttp3.'
        ]
    },
    'okio': {
        'name': "okio",
        'key': 'okio',
        'threadNamePrefix': 'Okio',
        'packages': [
            'okio.'
        ] 
    },
    'umeng': {
        'name': "友盟",
        'key': 'umeng',
        'threadNames': [
            'sensor_thread', # com.umeng.commonsdk.internal.utils.j.b
            'SL-NetWorkSender', # com.umeng.commonsdk.stateless.d
            'work_thread',  # com.umeng.commonsdk.framework.c
            'NetWorkSender', # com.umeng.commonsdk.framework.b
            'FileObserver' # com.umeng.commonsdk.framework.b.a
        ],
        'packages': [
            'com.umeng.'
        ]
    },
    'ttsdk': {
        'name': '穿山甲',
        'key': 'ttsdk',
        'packages': [
            'com.bytedance.',
            'com.ss.android.'
        ]
    },
    'gdt': {
        'name': '优量汇(广点通)',
        'key': 'gdt',
        'threadNames': [
            'GDT_ACTIVATE_LAUNCH',
            'GDT_VIDEO_CACHE',
            'gdt_stat_service',
            'GDT_IO_THREAD',
            'GDT_NET_THREAD',
            'GDT_DOWNLOAD_THREAD'
        ],
        'packages': [
            'com.qq.e.comm.'
        ]
    },
    'amap': {
        'name': '高德地图',
        'key': 'amap',
        'threadNames': [
            'amapLocManagerThread',
            'amapLocCoreThread'
        ],
        'packages': [
            'com.amap.'
        ]
    },
    'facebook': {
        'name': 'facebook',
        'key': 'facebook',
        'packages': [
            'com.facebook.'
        ]    
    },
    'huawei': {
        'name': '华为',
        'key': 'huawei',
        'packages': [
            'com.huawei.'
        ]
    },
    'networkbench': {
        'name': '听云',
        'key': 'networkbench',
        'packages': [
            'com.networkbench.'
        ]
    },
    'sina': {
        'name': '新浪',
        'key': 'sina',
        'packages': [
            'com.sina.',
            'com.weibo.ssosdk'
        ]
    }
}


def guessClassStartThreadFromThreadStackTrace(lines, lineNumber):
    '''
        return None or dict{
            'threadName': '',
            'threadNameLineNumber': lineNumber,
            'classStartThread': classStartThread,
            'stackTrace': [],
            'stackTraceLineNumberStart': lineNumberStart,
            'stackTraceLineNumberEnd': lineNumberEnd,
            'nextLineNumber': nextLineNumber
        }
    '''
    stackTraceLine = lines[lineNumber]
    threadTraceIndex = stackTraceLine.find(TAG_THREAD_STACK_TRACE)
    if threadTraceIndex == -1:
        return None

    depthStartIndex = stackTraceLine.find(TAG_THREAD_STACK_TRACE_DEPTH)
    if depthStartIndex == -1:
        return None

    depthStartIndex = depthStartIndex + TAG_THREAD_STACK_TRACE_DEPTH_LEN
    depthEndIndex = stackTraceLine[depthStartIndex:].find(',')
    if depthEndIndex == -1:
        return None

    depthEndIndex = depthStartIndex + depthEndIndex
    if len(stackTraceLine[depthStartIndex: depthEndIndex]) < 1:
        print(f"depth < 1, stackTraceLine is {stackTraceLine}, depthStartIndex={depthStartIndex}, depthEndIndex={depthEndIndex}")
    depth = int(stackTraceLine[depthStartIndex: depthEndIndex])

    lineNumber = lineNumber + 1
    stackTraceLineNumberStart = lineNumber
    depthIndex = 0
    stackTraceLine
    stackTrace = []
    while lineNumber < len(lines) and depthIndex < depth:
        stackTraceLine = lines[lineNumber]
        if stackTraceLine.find(TAG_THREAD_START) != -1 or stackTraceLine.find(TAG_THREAD_STACK_TRACE) != -1:
            # 遇到 ThreadStart 或者 printThreadStackTrace 则终止；
            break

        lineNumber += 1
        index = stackTraceLine.find(TAG_THREAD_TRACE_TRACE_ELEMENT)
        if index == -1:
            continue

        depthIndex += 1;
        stackTrace.append(stackTraceLine[index + TAG_THREAD_TRACE_TRACE_ELEMENT_LEN:])

    data = {
        'stackTrace': stackTrace,
        'stackTraceLineNumberStart': stackTraceLineNumberStart,
        'stackTraceLineNumberEnd': lineNumber - 1
    }

    for trace in stackTrace:
        if trace.startswith('java.util.') or trace.startswith('java.lang.'):
            continue
        data['classStartThread'] = trace
        break

    if stackTraceLine.find(TAG_THREAD_STACK_TRACE) != -1:
        # 处理连续多个 printThreadStackTrace 的情况
        data['nextLineNumber'] = lineNumber
        return data

    if lineNumber < len(lines):
        threadName = parseThreadName(lines[lineNumber], TAG_THREAD_START)
        if threadName is not None and len(threadName):
            data['threadName'] = threadName
            data['threadNameLineNumber'] = lineNumber

    data['nextLineNumber'] = lineNumber + 1
    return data
    
def parseThreadName(line, tag):
    '''
        return string thread name or None.
    '''
    nameStartIndex = line.find(TAG_NAME)
    if nameStartIndex == -1:
        return None

    tagIndex = line.find(tag)
    if tagIndex == -1:
        return None

    nameStartIndex = nameStartIndex + TAG_NAME_LEN
    nameEndIndex = line[nameStartIndex:].find(',')
    if nameEndIndex == -1:
        return None

    nameEndIndex = nameStartIndex + nameEndIndex
    threadName = line[nameStartIndex : nameEndIndex]
    # print(f"parseThreadName; line={line}, tag={tag}, nameStartIndex={nameStartIndex}, nameEndIndex={nameEndIndex}, return={threadName}")
    return threadName

def parseThreadLogFile(logFile):
    '''
        return dict {
            'threadStart' : threadStartList,
            'threadStartNum': len(threadStartList),
            'threadStartMissing': threadStartMissingList,
            'threadStartMissingNum': len(threadStartMissingList),
            'threadEnd': threadEndList,
            'threadEndNum': len(threadEndList)
        }
    '''
    lines = None
    with open(logFile) as f: 
        lines = f.read().splitlines()
    lineCount = len(lines)

    lineNumber = 0
    threadStartList = []
    threadStartMissingList = []
    while lineNumber < lineCount:
        data = guessClassStartThreadFromThreadStackTrace(lines, lineNumber)
        if data is not None:
            lineNumber = data.pop('nextLineNumber')
            # lineNumber = data['nextLineNumber']
            if 'threadName' not in data:
                threadStartMissingList.append(data)
            else:
                threadStartList.append(data)
        else:
            threadName = parseThreadName(lines[lineNumber], TAG_THREAD_START)
            if threadName is not None and len(threadName):
                threadStartMissingList.append({
                    'threadName': threadName, 
                    'threadNameLineNumber': lineNumber
                })
            lineNumber += 1

    lineNumber = 0
    threadEndList = []
    while lineNumber < lineCount:
        threadName = parseThreadName(lines[lineNumber], TAG_THREAD_END)
        lineNumber += 1
        if threadName is not None and len(threadName):
            threadEndList.append({
                'threadName': threadName, 
                'threadNameLineNumber': lineNumber
            })
    
    return {
        'threadStart' : threadStartList,
        'threadStartNum': len(threadStartList),
        'threadStartMissing': threadStartMissingList,
        'threadStartMissingNum': len(threadStartMissingList),
        'threadEnd': threadEndList,
        'threadEndNum': len(threadEndList)
    }

def classifyThread(threadNamesAndKey, threadNamePrefixsAndKey, packagesAndKey, threadInfo):
    '''
        return threadInfo classify
        1. 检测模块的threadNamesAndKey是否包含threadName, 如果包含，则将其归类到key对应的模块。
        2. 检测 threadName是否以 threadNamePrefix 开头，如果是，则将其归类到这个模块。
        3. 检测classStartThread类是否是某个模块的packages的前缀，如果是，则将其归类到key对应的模块。
        4. 为找到归属模块的的thread信息，则统一归类到unknown模块中。
    '''

    threadName = threadInfo.get('threadName')
    if threadName is not None:
        if threadName in threadNamesAndKey:
            return threadNamesAndKey[threadName]
        for threadNamePrefix in threadNamePrefixsAndKey:
            if threadName.startswith(threadNamePrefix):
                return threadNamePrefixsAndKey[threadNamePrefix]

    classStartThread = threadInfo.get('classStartThread')
    if classStartThread is not None:
        for package in packagesAndKey:
            if classStartThread.startswith(package):
                return packagesAndKey[package]

    return 'unknown'

def classify(result, modules):
    '''
        return classify thread by modules;
        1. 检测模块的 threadNames 是否包含 threadName , 如果包含，则将其归类到这个模块。
        2. 检测 threadName是否以 threadNamePrefix 开头，如果是，则将其归类到这个模块。
        3. 检测 classStartThread 类是否是某个模块的packages的前缀，如果是，则将其归类到这个模块。
        4. 为找到归属模块的的thread信息，则统一归类到unknown模块中。
    '''
    threadNamesAndKey = {}
    threadNamePrefixsAndKey = {}
    packagesAndKey = {}
    for key in modules:
        module = modules[key]
        if 'threadNames' in module:
            for item in module['threadNames']:
                threadNamesAndKey[item] = key
        if 'threadNamePrefix' in module:
            threadNamePrefixsAndKey[module['threadNamePrefix']] = key
        if 'packages' in module:
            for item in module['packages']:
                packagesAndKey[item] = key

    threadStartList = result['threadStart']
    for item in threadStartList:
        classify = classifyThread(threadNamesAndKey, threadNamePrefixsAndKey, packagesAndKey, item)
        item['module'] = classify
        module = modules[classify]
        module['count'] = module.get('count', 0) + 1
        moduleThreadStartList = module.get('threadStartList')
        if moduleThreadStartList is None:
            moduleThreadStartList = []
            module['threadStartList'] = moduleThreadStartList
        moduleThreadStartList.append(item)

    threadStartMissing = result['threadStartMissing']
    for item in threadStartMissing:
        classify = classifyThread(threadNamesAndKey, threadNamePrefixsAndKey, packagesAndKey, item)
        item['module'] = classify
        module = modules[classify]
        module['count'] = module.get('count', 0) + 1
        moduleThreadStartList = module.get('threadStartList')
        if moduleThreadStartList is None:
            moduleThreadStartList = []
            module['threadStartList'] = moduleThreadStartList
        moduleThreadStartList.append(item)

    return modules

def readJsonFile(jsonFilePath):
    '''
        parse json file.
    '''
    modules = None
    with open(jsonFilePath, 'r', encoding='utf8') as reader:
        modules = json.load(reader)
    print(f"read json from file {jsonFilePath}")
    return modules

def saveToJsonFile(result, fileName):
    '''
        format result to json and save to file name.
    '''
    resultJson = json.dumps(result, ensure_ascii=False)
    with open(fileName, 'w', encoding='utf8') as writer:
        writer.write(resultJson)
    print(f"write result to {fileName}")


def analyze(logFile, threadModulesFilePath, resultFileName):
    result = parseThreadLogFile(logFile)
    saveToJsonFile(result, resultFileName + '.origin.json')

    modules = readJsonFile(threadModulesFilePath)
    # modules = json.loads(json.dumps(THREAD_MODULES, ensure_ascii=False).encode('utf8'), encoding='utf8')
    classifyResult = classify(result, modules)
    saveToJsonFile(classifyResult, resultFileName + ".thread_start.classify.json")

if __name__ == "__main__":
    argvLen = len(sys.argv)
    print(f"argvLen={argvLen}, args={sys.argv}")

    if (argvLen < 1):
        print(f"usage: python3 src/sea_thread_log_analyzer.py path/to/thread_log.txt [path/to/thread_modules.json] [result file name]")
        exit(1)
    
    threadLogFilePath = sys.argv[1] if (argvLen > 1) else 'thread_log.txt'
    if not os.path.exists(threadLogFilePath):
        print(f"{threadLogFilePath} does not exists.")
        print(f"usage: python3 src/sea_thread_log_analyzer.py path/to/thread_log.txt [path/to/thread_modules.json] [result file name]")
        exit(1)

    threadModulesFilePath = sys.argv[2] if (argvLen > 2) else 'thread_modules.json'
    if not os.path.exists(threadLogFilePath):
        print(f"{threadModulesFilePath} does not exists.")
        print(f"usage: python3 src/sea_thread_log_analyzer.py path/to/thread_log.txt [path/to/thread_modules.json] [result file name]")
        exit(1)

    resultFileName = sys.argv[3] if(argvLen > 3) else 'result'
    analyze(threadLogFilePath, threadModulesFilePath, resultFileName)

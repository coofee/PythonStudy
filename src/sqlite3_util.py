#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import datetime
import os
import sys
import subprocess

def dictFactory(cursor, row):
    d = {}
    for index, col in enumerate(cursor.description):
        d[col[0]] = row[index]
    return d

def trace(function):
    def wrapper(*args, **kwargs):
        startTime = datetime.datetime.now()
        result = function(*args, **kwargs)
        endTime = datetime.datetime.now()
        delta = (endTime - startTime).microseconds / 1000.0
        print(f"[TRACE] {function.__name__} execute {delta} ms")
        return result
    return wrapper

def generateFileName(filename):
    return f"{datetime.datetime.now()}-{filename}".replace(":", "-").replace(' ', '_')

@trace
def generateDatabase(actionLogTextFilePath):
    """
    return generate databse file from actionLogTextFilePath.
    """

    print(f"start generateDatabase from {actionLogTextFilePath}")
    columnNamesString = ""
    with open(actionLogTextFilePath) as reader:
        columnNamesString = reader.readline()
    if len(columnNamesString) < 1:
        print(f"cannot get column names from {actionLogTextFilePath}")
    columnNamesString = columnNamesString.strip().replace('\t', ' text, ')
    sqlCreateActionLogTable = f"create table if not exists actionlog({columnNamesString} text);"
    databaseFile = generateFileName("actionlog.db")

    tableName = "actionlog"
    print(f"create table {tableName}")
    os.system(f"sqlite3 {databaseFile} '{sqlCreateActionLogTable};' ")

    print(f"start import data from {actionLogTextFilePath} to {tableName}")
    subprocess.call(["sqlite3", f"{databaseFile}",
        ".mode tabs",
        f".import {actionLogTextFilePath} {tableName}"
    ])
    print(f"end import data from {actionLogTextFilePath} to {tableName}")

    insertCount = os.system(f"sqlite3 {databaseFile} 'select count(*) from {tableName};' ")
    print(f"end generateDatabase from {actionLogTextFilePath}")
    return databaseFile

if __name__ == "__main__":
    """
    usage: python3 src/sqlite3_util.py path/to/actionlog.txt
    """
    argvLen = len(sys.argv)
    if argvLen > 1:
        generateDatabase(sys.argv[1])
    else:
        print(f"usage: python3 src/sqlite3_util.py path/to/actionlog.txt")
    
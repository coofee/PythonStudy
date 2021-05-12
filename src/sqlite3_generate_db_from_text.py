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
    # return f"{datetime.datetime.now()}-{filename}".replace(":", "-").replace(' ', '_')
    return filename

@trace
def generateDatabase(textFilePath, databaseFileName, tableName):
    """
    return generate databse file from textFilePath.
    """

    print(f"start generateDatabase from {textFilePath}")
    columnNamesString = ""
    with open(textFilePath) as reader:
        columnNamesString = reader.readline()
    if len(columnNamesString) < 1:
        print(f"cannot get column names from {textFilePath}")
    columnNamesString = columnNamesString.strip().replace('\t', ' text, ')
    sqlCreateTable = f"create table if not exists tableName({columnNamesString} text);"
    databaseFile = generateFileName(f"{databaseFileName}.db")

    print(f"create table {tableName}")
    os.system(f"sqlite3 {databaseFile} '{sqlCreateTable};' ")

    print(f"start import data from {textFilePath} to {tableName}")
    subprocess.call(["sqlite3", f"{databaseFile}",
        ".mode tabs",
        f".import {textFilePath} {tableName}"
    ])
    print(f"end import data from {textFilePath} to {tableName}")

    os.system(f"sqlite3 {databaseFile} 'select count(*) from {tableName};' ")
    print(f"end generateDatabase from {textFilePath}")
    return databaseFile

if __name__ == "__main__":
    """
    usage: python3 src/sqlite3_generate_db_from_text.py path/to/textFilePath.txt databaseName tableName
    """
    argvLen = len(sys.argv)
    if argvLen > 3:
        generateDatabase(sys.argv[1], sys.argv[2], sys.argv[3])
    else:
        print(f"usage: python3 src/sqlite3_generate_db_from_text.py path/to/tableName.txt databaseName tableName")
    
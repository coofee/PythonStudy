import os
from datetime import datetime
import shutil
import gzip
import zipfile
import sqlite3
import urllib.request
from urllib.parse import urlparse

DOWNLOAD_URLS = [
    "htttps://www.xxxx.com/xxxx.zip"
]

APP_ID_DICT: dict[int, str] = {
    2: "xxxx"
}

BUCKET_ID_DICT: dict[int, str] = {
    1: 'xxxx',
    2: 'xxxxsnapshot',
    3: 'xxxxcover',
    4: 'xxxxtransform',
    5: 'xxxxpic1'
}


def mkdirs(dir: str) -> str:
    if os.path.exists(dir):
        if os.path.isdir(dir):
            shutil.rmtree(dir)
        else:
            os.remove(dir)

    os.makedirs(dir, exist_ok=True)
    return dir


class DumpFileMetadata:

    def __init__(self, cid: str, appid: str, bucketid: str, filename: str, filesize: int, timestamp: str):
        self.cid = cid
        self.appid = appid
        self.bucketid = bucketid
        self.filename = filename
        self.filesize = filesize
        self.timestamp = timestamp

    def toTuple(self) -> tuple:
        return (self.cid, self.appid, self.bucketid, self.filename, self.filesize, self.timestamp)


class DumpFileDatabase:

    def __init__(self, nameOrPath: str) -> None:
        self.nameOrPath = nameOrPath
        self.connection = sqlite3.connect(self.nameOrPath)
        self.configDatabase()
        self.createTables()
        self.cursor = self.connection.cursor()

    def configDatabase(self):
        self.connection.isolation_level = None
        self.connection.execute('PRAGMA journal_mode = OFF')
        self.connection.execute('PRAGMA cache_size = 1000000')
        self.connection.execute('PRAGMA locking_mode = EXCLUSIVE')
        self.connection.execute('PRAGMA synchronous = OFF')

    def createTables(self):
        try:
            self.connection.executescript('''
                BEGIN;
                CREATE TABLE IF NOT EXISTS dump_files(
                    cid text,
                    appid text,
                    bucketid text,
                    filename text,
                    filesize integer,
                    timestamp text
                );
                COMMIT;
                ''')
            print(f"success create tables.")
            return True
        except:
            print(f"fail create tables.")
            return False

    def insertToDatabase(self, dumpFileMetadataList: list[DumpFileMetadata]) -> bool:
        try:
            print(f"try insert to database...")
            # metadataTupleList = list(metadata.toTuple()
            #                          for metadata in dumpFileMetadataList)
            # with self.connection:
            #     self.connection.executemany(
            #         "INSERT INTO dump_files(cid, appid, bucketid, filename, filesize, timestamp) VALUES(?, ?, ?, ?, ?, ?)", metadataTupleList)
            begin = datetime.utcnow()
            self.cursor.execute('BEGIN TRANSACTION;')
            for metadata in dumpFileMetadataList:
                self.cursor.execute(
                    "INSERT INTO dump_files(cid, appid, bucketid, filename, filesize, timestamp) VALUES(?, ?, ?, ?, ?, ?)", metadata.toTuple())
            self.cursor.execute('COMMIT;')

            cost = int((datetime.utcnow() - begin).total_seconds() * 1000)
            print(f"success insert to database, cost={cost}ms")
            return True
        except:
            self.cursor.execute('ROLLBACK;')
            print(f"fail insert to database.")
            return False

    def close(self):
        self.cursor.close()
        self.connection.close()


def downloadFile(url: str, savedFilePath: str) -> bool:
    print(f"try download {url}")
    try:
        parentDir = os.path.dirname(savedFilePath)
        if not os.path.exists(parentDir):
            os.makedirs(parentDir)

        urllib.request.urlretrieve(url, savedFilePath)
        print(f"success download {url} to {savedFilePath}")
        return True
    except:
        print(f"fail download {url} to {savedFilePath}")
        return False


def unzip(srcFile: str, extractDir: str) -> None:
    if not os.path.exists(srcFile):
        print(f"fail unzip for {srcFile} does not exists.")
        return False

    if not os.path.exists(extractDir):
        os.makedirs(extractDir)

    try:
        zip = zipfile.ZipFile(srcFile)
        zip.extractall(extractDir)
        zip.close()
        print(f"success unzip {srcFile} to {extractDir}")
        return True
    except:
        print(f"fail unzip {srcFile} to {extractDir}")
        return False


def parseDumpFile(dumpFile: str, appIdDict: dict[int, str], bucketIdDict: dict[int, str]) -> list[DumpFileMetadata]:
    print(f"begin parse dump file={dumpFile}")
    metadataList: list[DumpFileMetadata] = []
    with gzip.open(dumpFile, 'rt') as reader:
        while (line := reader.readline().rstrip()):
            # line data like below:
            # [cid:7] [appid:2] [bucketid:3] [filename:332330635658845720.thumb.jpg] [filesize:35970] [time:2021-06-29 17:11:45]
            itemList = list(item.strip('[]') for item in line.split('] ['))
            cid = itemList[0].split(':')[1]
            appid = appIdDict.get(int(itemList[1].split(':')[1]))
            bucketid = bucketIdDict.get(int(itemList[2].split(':')[1]))
            filename = itemList[3].split(":")[1]
            filesize = int(itemList[4].split(":")[1])
            timestamp = itemList[5][itemList[5].find(':') + 1:]
            metadataList.append(DumpFileMetadata(cid=cid, appid=appid, bucketid=bucketid,
                                filename=filename, filesize=filesize, timestamp=timestamp))
    print(f"success parse dump count={len(metadataList)}, file={dumpFile}, ")
    return metadataList


def parseFileNameFromUrl(url: str) -> str:
    paths = urlparse(url=url).path.split('/')
    lastPath = paths[len(paths) - 1]
    return lastPath


def trimFileExtensionName(filename: str) -> str:
    lastPointIndex = filename.rfind('.')
    if lastPointIndex != -1:
        return filename[0:lastPointIndex]
    else:
        return filename


def absoluteFilePaths(directory):
    for dirpath, _, filenames in os.walk(directory):
        for f in filenames:
            yield os.path.abspath(os.path.join(dirpath, f))


class Config:
    def __init__(self, urls: list[str], appIdDict: dict[int, str], bucketIdDict: dict[int, str], downloadDir: str, database: str) -> None:
        self.urls = urls
        self.appIdDict = appIdDict
        self.bucketIdDict = bucketIdDict
        self.downloadDir = downloadDir
        self.database = database


def main(config: Config):
    dumpFileList: list[str] = []
    for index, url in enumerate(config.urls):
        filename = parseFileNameFromUrl(url=url)
        downloadFilePath = os.path.join(config.downloadDir, filename)

        if downloadFile(url=url, savedFilePath=downloadFilePath):
            extractDir = os.path.join(
                config.downloadDir, trimFileExtensionName(filename))

            if unzip(srcFile=downloadFilePath, extractDir=extractDir):
                extraFileList = list(absoluteFilePaths(extractDir))
                dumpFileList += extraFileList

    database: DumpFileDatabase = DumpFileDatabase(nameOrPath=config.database)
    for index, f in enumerate(dumpFileList):
        metadataList = parseDumpFile(dumpFile=f, appIdDict=config.appIdDict,
                                     bucketIdDict=config.bucketIdDict)
        if database.insertToDatabase(metadataList):
            print(f"{index} success insert to database, count={len(metadataList)}")
        else:
            print(f"{index} fail insert to database, count={len(metadataList)}")
    database.close()
    print(f"done.")


if __name__ == '__main__':
    outputDir = mkdirs(os.path.join(os.getcwd(), 'output'))
    downloadDir = mkdirs(os.path.join(outputDir, 'download'))
    database = os.path.join(outputDir, 'dump_files.db')

    config = Config(
        urls=DOWNLOAD_URLS,
        appIdDict=APP_ID_DICT,
        bucketIdDict=BUCKET_ID_DICT,
        downloadDir=downloadDir,
        database=database
    )

    main(config=config)

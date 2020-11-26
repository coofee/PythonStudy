#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import json
import sys
import sqlite3

import numpy as np
import matplotlib.pyplot as plt

import sqlite3_util

DECODE_SUCCESS = 1
ROW_COUNT_TEST = 10

class Analyzer():

    STATS_SQL = """
SELECT 
    s.decode_type,
    s.success_count, 
    s.fail_count,
    (s.success_count * 1.0/ (s.success_count + s.fail_count)) as success_rate,
    (s.fail_count * 1.0 / (s.success_count + s.fail_count)) as fail_rate,	
    s.total_decode_time, 
    (s.total_decode_time * 1.0 / s.success_count) as avg_decode_time,
    mode.decode_time as mode_decode_time,
    mode.decode_times as mode_decode_times,
    (mode.decode_times * 1.0 / (s.success_count + s.fail_count)) as mode_decode_times_rate
FROM 
    summary as s,  
    ( 
        SELECT * 
        FROM output 
        GROUP BY decode_type 
        HAVING max(decode_times)
    ) as mode
WHERE s.decode_type = mode.decode_type
        """

    def __init__(self):
        self.plainDecodeResult = DecodeResult()
        self.brotliDecodeResult = DecodeResult()

    @sqlite3_util.trace
    def analyze(self, actionLogTextFilePath):
        dbPath = sqlite3_util.generateDatabase(actionLogTextFilePath)
        self.__parseDecodeInfoFromDatabase(dbPath)
        outputPath = sqlite3_util.generateFileName("output.db")
        self.__outputDecodeInfoToDatabase(outputPath)
        self.printStatsInfo(outputPath)

    @sqlite3_util.trace
    def __parseDecodeInfoFromDatabase(self, dbPath):
        print(f"try parse input databse={dbPath}")
        connection = sqlite3.connect(dbPath)
        connection.row_factory = sqlite3_util.dictFactory
        cursor = connection.cursor()
        pageType = 'tzcompression'
        actionType = 'statistics'
        sql = f"select * from actionlog where pagetype='{pageType}' and actiontype='{actionType}'"
        print(f"try execute {sql}")
        cursor.execute(sql)
        for row in cursor:
            wuxianData = json.loads(row['wuxian_data'])
            wuxianDataJson = wuxianData["json"]
            self.plainDecodeResult.add(wuxianDataJson["plain.d.state"], wuxianDataJson["plain.d.time"])
            self.brotliDecodeResult.add(wuxianDataJson["brotli.d.state"], wuxianDataJson["brotli.d.time"])
        print(f"plainDecodeResult={self.plainDecodeResult}")
        print(f"brotliDecodeResult={self.brotliDecodeResult}")
        print(f"end execute {sql}")
        print(f"end parse input database={dbPath}.")
        cursor.close()
        connection.close()

    @sqlite3_util.trace
    def __outputDecodeInfoToDatabase(self, outputPath):
        print(f"try output to database {outputPath}")
        connection = sqlite3.connect(outputPath)
        connection.row_factory = sqlite3_util.dictFactory

        connection.execute("""create table if not exists summary(
            success_count integer,
            fail_count integer,
            total_decode_time integer,
            decode_type text
        )""")
        connection.executemany("""
            insert into summary(success_count, fail_count, total_decode_time, decode_type) 
            values(?, ?, ?, ?)
        """, [
            (self.plainDecodeResult.successCount, self.plainDecodeResult.failCount, self.plainDecodeResult.totalTime, 'plain'),
            (self.brotliDecodeResult.successCount, self.brotliDecodeResult.failCount, self.brotliDecodeResult.totalTime, 'brotli')
        ])
        connection.commit()

        connection.execute("""create table if not exists output(
            decode_time integer,
            decode_times integer,
            decode_type text
        )""")
        outputs = []
        for key, value in self.plainDecodeResult.timeDict.items():
            outputs.append((key, value, 'plain'))
        for key, value in self.brotliDecodeResult.timeDict.items():
            outputs.append((key, value, 'brotli'))
        connection.executemany("""
            insert into output(decode_time, decode_times, decode_type)
            values(?, ?, ?)
        """, outputs)
        connection.commit()
        connection.close()
        print(f"end output to database {outputPath}")

    @sqlite3_util.trace
    def printStatsInfo(self, dbPath):
        connection = sqlite3.connect(dbPath)
        # connection.row_factory = dictFactory
        cursor = connection.cursor()
        cursor.execute(Analyzer.STATS_SQL)
        names = [description[0] for description in cursor.description]
        sep = ' | '
        print(f"{sep.join(str(x) for x in names )}")
        for row in cursor:
            print(f"{sep.join(str(x) for x in row)}")

        plainDecodeTimesMax = 0
        plainDecodeTimeMax = 0
        brotliDecodeTimesMax = 0
        brotliDecodeTimeMax = 0
        cursor.execute("SELECT max(decode_times) as decode_times_max, decode_type, max(decode_time) as decode_time_max FROM output GROUP BY decode_type")
        for row in cursor:
            decodeType = row[1]
            if 'plain' == decodeType:
                plainDecodeTimesMax = row[0]
                plainDecodeTimeMax = row[2]
            elif 'brotli' == decodeType:
                brotliDecodeTimesMax = row[0]
                brotliDecodeTimeMax = row[2]
            else:
                print(f"cannot handle decode_type={decodeType}")

        self.__outputGraph(cursor, plainDecodeTimeMax, plainDecodeTimesMax, brotliDecodeTimeMax, brotliDecodeTimesMax)
        cursor.close()
        connection.close()
    
    def __outputGraph(self, cursor, plainDecodeTimeMax, plainDecodeTimesMax, brotliDecodeTimeMax, brotliDecodeTimesMax):
        cursor.execute("SELECT decode_time, decode_times FROM output WHERE decode_type = 'plain' order by decode_times desc")
        plainX = []
        plainY = []
        plainAreas = []
        for row in cursor:
            plainX.append(row[0])
            plainY.append(row[1])
            plainAreas.append(max(row[1] * 400.0 / plainDecodeTimesMax, 1))
        # print(f"plainX={plainX}, plainY={plainY}, plainAreas={plainAreas}")

        cursor.execute("SELECT decode_time, decode_times FROM output WHERE decode_type = 'brotli' order by decode_times desc")
        brotliX = []
        brotliY = []
        brotliAreas = []
        for row in cursor:
            brotliX.append(row[0])
            brotliY.append(row[1])
            brotliAreas.append(max(row[1] * 400.0 / brotliDecodeTimesMax, 1))
        # print(f"brotliX={brotliX}, brotliY={brotliY}, brotliAreas={brotliAreas}")

        # 取消科学计数法
        gca = plt.gca()
        gca.get_yaxis().get_major_formatter().set_scientific(False)
        gca.get_xaxis().get_major_formatter().set_scientific(False)

        # 设置坐标轴
        decodeTimeMax = max(plainDecodeTimeMax, brotliDecodeTimeMax)
        # xIndex = [0, 10, 100, 1_000, 10_000, 100_000, 1_000_000, decodeTimeMax]
        # x = np.linspace(0, decodeTimeMax, num=len(xIndex))

        decodeTimesMax = max(plainDecodeTimesMax, brotliDecodeTimesMax)
        # yIndex = [0, 10, 100, 1_000, 10_000, 100_000, 1_000_000, decodeTimesMax]
        # y = np.linspace(0, decodeTimesMax, num=len(yIndex))
        # # rotation用来旋转x坐标轴刻度角度
        # plt.xticks(x, np.array(xIndex), rotation=30)
        # plt.yticks(y, np.array(yIndex))

        # bax = brokenaxes(
        #     xlims=((0, 10), (10, 100), (100, 1000), (1000, 10_000), (10_000, 100_000), (100_000, 1_000_000), (1_000_000, decodeTimeMax)),
        #     ylims=((0, 10), (10, 100), (100, 1000), (1000, 10_000), (10_000, 100_000), (100_000, 1_000_000), (1_000_000, decodeTimesMax)),
        #     width_ratios=[1, 1]
        # )

        plt.xlabel("time")
        plt.xticks(rotation=30)

        plt.ylabel("times")
        plt.scatter(np.array(brotliX), np.array(brotliY), s=brotliAreas, c='blue', alpha=0.5)
        plt.scatter(np.array(plainX), np.array(plainY), s=plainAreas, c='red', alpha=0.5)
        plt.title('scatter(plain=red; brotli=blue)')
        scatterFigure = sqlite3_util.generateFileName("plain_vs_brotli_scatter.png")
        plt.savefig(scatterFigure)


        # 饼图
        plainDecodeSuccessCount = self.plainDecodeResult.successCount
        if plainDecodeSuccessCount == 0:
            plainDecodeSuccessCount = 5726111
        brotliDecodeSuccessCount = self.brotliDecodeResult.successCount
        if brotliDecodeSuccessCount == 0:
            brotliDecodeSuccessCount = 5726071
        print(f"plainDecodeSuccessCount={plainDecodeSuccessCount}, brotliDecodeSuccessCount={brotliDecodeSuccessCount}")

        sep = 50
        top = min(15, len(plainY))
        plainYPercent = [ x * 100.0 / plainDecodeSuccessCount for x in plainY]
        plainYPercentTop = plainYPercent[0:top - 1]
        plainYPercentTopLabel = plainX[0:top - 1]

        start = plainX[top - 1]
        plainRangeCount = 0
        largeThanSepCount = 0
        for index in range(len(plainX)):
            x = plainX[index]
            if x >= start and x < sep:
                plainRangeCount += plainY[index]
            elif x >= sep:
                largeThanSepCount += plainY[index]
        
        plainYPercentTopLabel.append(f"{start}-{sep - 1}")
        plainYPercentTop.append(plainRangeCount * 100.0 / plainDecodeSuccessCount)
        
        if largeThanSepCount > 0:
            plainYPercentTopLabel.append("others")
            plainYPercentTop.append(largeThanSepCount * 100.0 / plainDecodeSuccessCount)

        fig1, ax1 = plt.subplots()
        ax1.pie(plainYPercentTop, labels=plainYPercentTopLabel, autopct='%1.1f%%', shadow=True, startangle=0)
        ax1.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
        plt.title(f"plain with top {top}")
        plainTopPieFigure = sqlite3_util.generateFileName(f"plain_with_top_{top}_pie.png")
        plt.savefig(plainTopPieFigure)

        # 因为brotli解析分散的比较多，所以先分组，再画图
        cursor.execute(f"""SELECT min(decode_time), max(decode_time), sum(decode_times) FROM output 
            WHERE decode_type = "brotli" 
            GROUP BY (decode_time / {sep})
            ORDER BY decode_times DESC
            LIMIT {top}"""
        )

        brotliGroupBy = []
        brotliGroupByLabel = []
        brotliTopCount = 0
        for row in cursor:
            brotliGroupByLabel.append(f"{row[0]}-{row[1]}")
            brotliTopCount += row[2]
            brotliGroupBy.append(row[2] * 100.0 / brotliDecodeSuccessCount)
        brotliGroupByLabel.append("others")
        brotliGroupBy.append((brotliDecodeSuccessCount - brotliTopCount) * 100.0 / brotliDecodeSuccessCount)

        fig1, ax1 = plt.subplots()
        ax1.pie(brotliGroupBy, labels=brotliGroupByLabel, autopct='%1.1f%%', shadow=True, startangle=0)
        ax1.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
        plt.title(f"brotli with top {top}")
        brotliTopPieFigure = sqlite3_util.generateFileName(f"brotli_with_top_{top}_pie.png")
        plt.savefig(brotliTopPieFigure)


class DecodeResult():

    def __init__(self): 
        self.totalTime = 0
        self.successCount = 0
        self.failCount = 0
        self.timeDict = {}

    def totalTime(self):
        """
        返回总时间
        """
        return self.totalTime

    def averageTime(self):
        """
        返回平均时间
        """
        return self.totalTime * 1.0 / self.successCount

    def modeTime(self):
        """
        返回时间众数
        """
        maxTimes = 0
        modeTime = 0
        for key, value in self.timeDict.items():
            if value > maxTimes:
                modeTime = key
                maxTimes = value
        return modeTime

    def add(self, decodeState, decodeTime):
        if DECODE_SUCCESS == int(decodeState):
            self.successCount += 1
            decodeTimeInt = int(decodeTime)
            self.totalTime += decodeTimeInt
            self.__add(decodeTimeInt)
        else:
            self.failCount += 1

    def __add(self, decodeTime):
        times = self.timeDict.get(decodeTime, None)
        if times is None:
            times = 1
        else:
            times += 1
        self.timeDict[decodeTime] = times

    def __str__(self):
        timeDictSize = len(self.timeDict)
        print(f"timeDict.size={timeDictSize}")
        return f"DecodeResult successCount={self.successCount}, failCount={self.failCount},  totalTime={self.totalTime}, averageTime={self.averageTime()}, modeTime={self.modeTime()}, timeDict={self.timeDict}"

def main():
    argvLen = len(sys.argv)
    if (argvLen < 2):
        print(f"usage: python analyzer_brotli.py (import|analyze|stats) (input file)")
        return

    command = sys.argv[1]
    if "import" == command:
        sqlite3_util.generateDatabase(sys.argv[2])
    elif "analyze" == command:
        Analyzer().analyze(sys.argv[2])
    elif "stats" == command:
        Analyzer().printStatsInfo("output_info.db")
    else:
        print(f"cannot handle command={command}")

if __name__ == "__main__":
    """
    python3 src/analyzer_brotli.py analyze actionlog.txt
    """
    main()
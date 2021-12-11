import os
import datetime
import time
import shutil
from concurrent.futures import ProcessPoolExecutor

def executeCommand(cmd):
    try:
        print(f"{datetime.datetime.now()}: start excute {cmd}")
        os.system(cmd)
        print(f"{datetime.datetime.now()}: end execute {cmd}")
    except:
        print(f"{datetime.datetime.now()}: fail execute {cmd}")

def launchAndRecordAppStartUp(launchAppCommand, stopAppCommand, maxCount, prefix):
    for index in range(maxCount):
        os.system(stopAppCommand)
        os.system('sleep 1')

        fileName = f"{prefix}_record_{index}"

        # 录屏和打开app命令
        commands = [
            f"adb shell screenrecord --time-limit 10 --size 1280x720 --verbose /sdcard/{fileName}.mp4",
            launchAppCommand
        ]

        # 并行运行命令
        with ProcessPoolExecutor(max_workers=2) as executor:
            for command in commands:
                executor.submit(executeCommand, command)
                time.sleep(1)

            executor.shutdown(wait=True)

        # 获取录屏文件
        os.system(f"adb pull /sdcard/{fileName}.mp4 ./{fileName}.mp4")

        # 视频分帧
        imageDir = os.path.join(os.path.curdir, fileName)
        shutil.rmtree(imageDir, ignore_errors=True)
        os.mkdir(imageDir)
        os.system(f"ffmpeg -i ./{fileName}.mp4 -vf fps=60 ./{imageDir}/image_%d.png")


if __name__ == "__main__":
    launchAppCommmand = "adb shell am start-activity -W -n com.wuba/.activity.launch.LaunchActivity --ei report_type 1"
    stopAppCommand = 'adb shell am force-stop com.wuba'
    launchAndRecordAppStartUp(launchAppCommmand, stopAppCommand, 1, 's1')


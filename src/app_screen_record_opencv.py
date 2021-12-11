import os
import datetime
import time
import shutil
import cv2

from concurrent.futures import ProcessPoolExecutor


def executeCommand(cmd):
    try:
        print(f"{datetime.datetime.now()}: start excute {cmd}")
        os.system(cmd)
        print(f"{datetime.datetime.now()}: end execute {cmd}")
    except:
        print(f"{datetime.datetime.now()}: fail execute {cmd}")

def convertVideoToImageFrame(video, imageDir):
    capture = cv2.VideoCapture(video)
    fps = capture.get(cv2.CAP_PROP_FPS)
    frameCount = capture.get(cv2.CAP_PROP_FRAME_COUNT)
    print(f"video fps={fps} frame count={frameCount}")
    count = 0
    while True:
        success, image = capture.read()
        frameTime = capture.get(cv2.CAP_PROP_POS_MSEC)
        if not success:
            print(f"fail read image frame {count}")
            break
        imageFile = os.path.join(imageDir, f"frame_{count}_{frameTime}.png")
        cv2.imwrite(imageFile, image)
        count += 1
    print(f"save all image frame {count} to {imageDir}")

def mkdirs(dir):
    if os.path.exists(dir):
        shutil.rmtree(dir, ignore_errors=True)
    else:
        os.makedirs(dir)

def launchAndRecordAppStartUp(launchAppCommand, stopAppCommand, maxCount, prefix):
    outputDir = os.path.join(os.path.curdir, 'output')
    mkdirs(outputDir)

    for index in range(maxCount):
        os.system(stopAppCommand)
        os.system('sleep 1')

        fileName = f"{prefix}_record_{index}"

        # 录屏和打开app命令
        commands = [
            # f"adb shell screenrecord --time-limit 10 --size 1280x720 --verbose /sdcard/{fileName}.mp4",
            f"adb shell screenrecord --time-limit 10 --verbose /sdcard/{fileName}.mp4",
            launchAppCommand
        ]

        # 并行运行命令
        with ProcessPoolExecutor(max_workers=2) as executor:
            for command in commands:
                executor.submit(executeCommand, command)
                time.sleep(1)

            executor.shutdown(wait=True)

        # 获取录屏文件
        recordVideoFile = os.path.join(outputDir, f"{fileName}.mp4")
        os.system(f"adb pull /sdcard/{fileName}.mp4 {recordVideoFile}")

        # 视频分帧
        imageDir = os.path.join(outputDir, fileName)
        mkdirs(imageDir)
        convertVideoToImageFrame(recordVideoFile, imageDir)


if __name__ == "__main__":
    launchAppCommmand = "adb shell am start-activity -W -n com.wuba/.activity.launch.LaunchActivity --ei report_type 1"
    stopAppCommand = 'adb shell am force-stop com.wuba'
    launchAndRecordAppStartUp(launchAppCommmand, stopAppCommand, 1, 's1')


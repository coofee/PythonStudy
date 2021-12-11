from PIL import Image
import PIL

import imgcompare

path1 = "/Users/zhaocongying/program/git_proj/github.com/PythonStudy/s1_record_0/frame_72_4855.944444444445.png"
path2 = "/Users/zhaocongying/program/git_proj/github.com/PythonStudy/s1_record_0/frame_66_3557.7555555555555.png"

image1 = Image.open(path1)
image2 = Image.open(path2)

diffPercent = imgcompare.image_diff_percent(image2, image1)
print(f"diff percent is {diffPercent}")

diffPercent = imgcompare.image_diff_percent(path1, path2)
print(f"diff percent is {diffPercent}")

#   adb shell am force-stop com.wuba
#   sleep 1
#   adb shell am start-activity -W -n com.wuba/.activity.launch.LaunchActivity --ei report_type 1
#   sleep 10


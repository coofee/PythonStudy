import os
import sys
import time

from urllib.parse import  quote_plus


INTENT_DATA_URI_START_FROM = "app.launch.intent: Intent { dat="
INTENT_DATA_URI_END_TO = " flg=0x"

def parseExtraMessage(extraMessageFilePath):
    dataUri = None
    with open(extraMessageFilePath) as reader:
        for line in reader.readlines():
            if len(line) < 1 or not line.startswith(INTENT_DATA_URI_START_FROM):
                continue
            dataUriStartPosition = len(INTENT_DATA_URI_START_FROM)
            dataUriEndPosition = line.index(INTENT_DATA_URI_END_TO)
            if (dataUriEndPosition > dataUriStartPosition):
                dataUri = line[dataUriStartPosition:dataUriEndPosition]
                break
    print(f"parseExtraMessage; extraMessageFilePath={extraMessageFilePath} dataUri={dataUri}")
    return dataUri

def encodeDataUri(dataUri):
    # dataUri.find("?params={")
    # dataUri=wbutown://jump/town/common?params={}
    if dataUri is None or dataUri.find("?params=") < 1:
        return None

    paramJsonStartPosition = dataUri.index("?params=") + len("?params=")
    paramJson = dataUri[paramJsonStartPosition:]
    print(f"encodeDataUri; paramJson={paramJson}")

    # urlencode json string
    paramJsonEncoded = quote_plus(paramJson)
    print(f"encodeDataUri; paramJsonEncoded={paramJsonEncoded}")
    dataUriEncoded = f"{dataUri[:paramJsonStartPosition]}{paramJsonEncoded}"

    print(f"encodeDataUri; encodeDataUri={dataUriEncoded}")
    return dataUriEncoded

def launch(dataUri):
    if dataUri is None:
        return

    command = f"adb shell am start -a android.intent.action.VIEW -d \"{dataUri}\""
    print(f"launch; execute command={command}")
    os.system(command)

def executeFile(filePath):
    print(f"executeFile; filePath={filePath}")
    dataUri = parseExtraMessage(filePath)
    dataUriEncoded = encodeDataUri(dataUri)
    launch(dataUriEncoded)

def executeFileDirectory(filePath):
    for file in os.listdir(filePath):
        executeFile(os.path.join(filePath, file))
        time.sleep(5)

if __name__ == "__main__":
    argvLen = len(sys.argv)
    print(f"argvLen={argvLen}, args={sys.argv}")

    if (argvLen < 2):
        print(f"usage: python3 src/launch_app.py path/to/extraMessage")
        exit(1)
    
    filePath = sys.argv[1]
    if os.path.isfile(filePath):
        if filePath.endswith('.zip'):
            extraDir = os.path.join(os.path.curdir, "extra")
            os.system(f"unzip -o {filePath} -d {extraDir}")
            executeFileDirectory(extraDir)
        else:
            executeFile(filePath)
    elif os.path.isdir(filePath):
        executeFileDirectory(filePath)
    else:
        print(f"usage: python3 src/launch_app.py path/to/extraMessage")
        exit(1)

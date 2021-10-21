#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

# python3 frida_shadow_test.py
# frida -U Gadget -l frida_hook.js

import frida

def read_js_code(js_file):
    with open(js_file) as f:
        return f.read()

def on_message(message, data):
    print(f"message={message}, data={data}")

def hook(code):
    print(f"code={code}")
    deviceManager = frida.get_device_manager()
    device = deviceManager.get_usb_device()
    print(f"usb device={device}")
    # device = deviceManager.get_remote_device()
    # print(f"remote device={device}")
    # pid = device.spawn(["com.coofee.shadow"])
    # print(f"pid={pid}")
    # session = device.attach(pid)
    session = device.attach('Gadget')
    script = session.create_script(code)
    script.on("message", on_message)
    script.load()
    # device.resume(pid)
    # session.detach()
    input()

if __name__ == "__main__":
    hook(read_js_code('frida_hook.js'))


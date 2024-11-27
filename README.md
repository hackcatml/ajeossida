# Ajeossida (아저씨다)
Frida with patches that definitively fix basic detection points on Android and iOS.<br> 
Unfortunately, I discovered that the patches in several custom Frida builds for bypassing detections are incomplete and still detectable.<br>
For example, `frida_agent_main` in memory and the `gum-js-loop` thread name.<br> 
Therefore, I created a Python build script to address these issues.

Since this is a manual patch that doesn't automatically follow the Frida upstream,<br> 
I will occasionally build it, verify that the patch works properly, and then release it.

# Patches
- Android
- [x] No `frida_agent_main` in memory<br>
- [x] No `gum-js-loop, gmain, gdbus, frida-gadget` thread name in `/proc/<pid>/task/<thread_id>/status`<br>
- [x] No `libfrida-agent-raw.so` in linker's so list
- [x] No libc hooking<br>

- iOS
- [x] No `frida_agent_main` in memory<br>
- [x] No `gum-js-loop, gmain, gdbus, pool-frida, pool-spawner` thread name<br>
- [x] No `/usr/lib/frida/` 
- [x] No `exit, abort, task_threads` hooking<br>

# Run
- MacOS<br>
Output: server, gadget (Android, iOS)<br>
`python3 main_macos.py`

- Ubuntu 22.04<br>
Output: server, gagdet (Android)<br>
`python3 main_ubuntu.py`

# MagiskAjeossida
* A magisk module that automatically runs ajeossida-server on boot.  
* To run it in remote mode, use the following command. It will listen on `0.0.0.0:45678`.  
`adb shell "su -c sed -i 's/REMOTE=0/REMOTE=1/' /data/adb/modules/magisk_ajeossida/service.sh"`
* You can attach Frida to a pairipcore protected app using this module.  
However, the app will crash after a few seconds. Bypassing the crash is up to you. (Spawning the app also causes it to crash)

# Contact
- Channel: https://t.me/hackcatml1
- Chat: https://t.me/hackcatmlchat

# References
- [strongR-frida-android](https://github.com/hzzheyang/strongR-frida-android)<br>
- [Florida](https://github.com/Ylarod/Florida)
- [magisk-frida](https://github.com/ViRb3/magisk-frida)


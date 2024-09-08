# Ajeossida (아저씨다)
Frida with patches that definitively fix basic detection points.<br> 
Unfortunately, I discovered that the patches in several custom Frida builds for bypassing detections are incomplete and still detectable.<br>
For example, `frida_agent_main` in memory and the `gum-js-loop` thread name.<br> 
Therefore, I created a Python build script to address these issues (this script is only tested on macOS).

Since this is a manual patch that doesn't automatically follow the Frida upstream,<br> 
I will occasionally build it, verify that the patch works properly, and then release it.

# Patches
- [x] No `frida_agent_main` in memory<br>
- [x] No `gum-js-loop, gmain, gdbus, frida-gadget` thread name in `/proc/<pid>/task/<thread_id>/status`<br>
- [x] No `libfrida-agent-raw.so` in linker's so list
- [x] No libc hooking<br>

# Contact
- Channel: https://t.me/hackcatml1
- Chat: https://t.me/hackcatmlchat

# References
- [strongR-frida-android](https://github.com/hzzheyang/strongR-frida-android)<br>
- [Florida](https://github.com/Ylarod/Florida)


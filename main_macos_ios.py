import gzip
import os
import shutil
import subprocess
import sys

CUSTOM_NAME = "ajeossida"


def run_command(command, cwd=None):
    try:
        result = subprocess.run(command, shell=True, cwd=cwd, check=True, text=True)
        return result.returncode
    except subprocess.CalledProcessError as e:
        print(f"Error while running command: {command}\nError: {e}")
        if "ios" in cwd:
            # frida-helper patch
            print(f"\n[*] Patch 'get_frida_helper_' with 'get_{CUSTOM_NAME}_helper_' recursively...")
            patch_strings = ["get_frida_helper_"]
            for patch_string in patch_strings:
                replace_strings_in_files(os.path.join(os.getcwd(), CUSTOM_NAME), patch_string,
                                         patch_string.replace("frida", f"{CUSTOM_NAME}"))
            # frida-agent patch
            print(f"\n[*] Patch 'get_frida_agent_' with 'get_{CUSTOM_NAME}_agent_' recursively...")
            patch_strings = ["get_frida_agent_"]
            for patch_string in patch_strings:
                replace_strings_in_files(os.path.join(os.getcwd(), CUSTOM_NAME), patch_string,
                                         patch_string.replace("frida", f"{CUSTOM_NAME}"))
            # build again
            build(cwd)
        else:
            sys.exit(1)


def git_clone_repo():
    repo_url = "https://github.com/frida/frida.git"
    destination_dir = os.path.join(os.getcwd(), CUSTOM_NAME)

    print(f"\n[*] Cloning repository {repo_url} to {destination_dir}...")
    run_command(f"git clone --recurse-submodules {repo_url} {destination_dir}")


def configure_build(arch):
    build_dir = os.path.join(os.getcwd(), CUSTOM_NAME, arch)
    os.makedirs(build_dir, exist_ok=True)

    ios_keychain = "frida-signing"
    print(f"\n[*] Check {ios_keychain}...")
    result = subprocess.run(f"security find-identity -v -p codesigning | grep {ios_keychain}", shell=True, text=False)
    if result.returncode != 0:
        print("\n[!] Cannot find \"frida-signing\" keychain")
        sys.exit(1)
    print(f"\n[*] Set 'MACOS_CERTID' and 'IOS_CERTID' environment variables with {ios_keychain}")
    os.environ['MACOS_CERTID'] = ios_keychain
    os.environ['IOS_CERTID'] = ios_keychain

    print(f"\n[*] Configuring the build for {arch}...")
    result = run_command(
        f"{os.path.join('..', 'configure')} --prefix=/usr --host={arch} --enable-portal -- -Dfrida-gum:devkits=gum,gumjs -Dfrida-core:assets=installed -Dfrida-core:devkits=core",
        cwd=build_dir)

    if result == 0:
        return build_dir
    else:
        print("\n[!] Failed to configure")
        sys.exit(1)


def build(build_dir):
    run_command("make", cwd=build_dir)


def replace_strings_in_files(directory, search_string, replace_string):
    if os.path.isfile(directory):
        file_path = directory
        with open(file_path, 'r+', encoding='utf-8') as file:
            content = file.read()
            if search_string in content:
                print(f"Patch {file.name}")
                patched_content = content.replace(search_string, replace_string)
                file.seek(0)
                file.write(patched_content)
                file.truncate()
    else:
        for root, dirs, files in os.walk(directory):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                try:
                    with open(file_path, 'r+', encoding='utf-8') as file:
                        content = file.read()
                        if search_string in content:
                            print(f"Patch {file.name}")
                            patched_content = content.replace(search_string, replace_string)
                            file.seek(0)
                            file.write(patched_content)
                            file.truncate()
                except Exception as e:
                    pass


def capitalize_first_lower_char(word):
    for index, char in enumerate(word):
        if char.islower():
            # Replace the first lowercase character with its uppercase equivalent
            return word[:index] + char.upper() + word[index + 1:]
    return word


def main():
    custom_dir = os.path.join(os.getcwd(), CUSTOM_NAME)
    if os.path.exists(custom_dir):
        print(f"\n[*] Cleaning {custom_dir}...")
        shutil.rmtree(custom_dir)

    assets_dir = os.path.join(os.getcwd(), "assets")
    if os.path.exists(assets_dir):
        print(f"\n[*] Cleaning {assets_dir}...")
        shutil.rmtree(assets_dir)
    os.mkdir(assets_dir)

    ios_assets_dir = os.path.join(os.getcwd(), "ios-assets")
    if os.path.exists(ios_assets_dir):
        print(f"\n[*] Cleaning {ios_assets_dir}...")
        shutil.rmtree(ios_assets_dir)
    ios_assets_frida_server_dir = os.path.join(ios_assets_dir, 'usr/bin')
    ios_assets_frida_agent_dir = os.path.join(ios_assets_dir, f'usr/lib/{CUSTOM_NAME}')
    os.makedirs(ios_assets_frida_server_dir, exist_ok=True)
    os.makedirs(ios_assets_frida_agent_dir, exist_ok=True)

    git_clone_repo()

    architectures = ["ios-arm64e"]
    build_dirs = [configure_build(arch) for arch in architectures]

    # re.frida.server patch
    print(f"\n[*] Patch 're.frida.server' with 're.{CUSTOM_NAME}.server' recursively...")
    patch_string = "re.frida.server"
    replace_strings_in_files(custom_dir,
                             patch_string,
                             patch_string.replace("frida", CUSTOM_NAME))

    # frida-helper patch
    print(f"\n[*] Patch 'frida-helper' with '{CUSTOM_NAME}-helper' recursively...")
    patch_strings = ["frida-helper-32", "frida-helper-64", "get_frida_helper_", "\"/frida-\""]
    for patch_string in patch_strings:
        replace_strings_in_files(custom_dir,
                                 patch_string,
                                 patch_string.replace("frida", CUSTOM_NAME))

    # frida-agent patch
    print(f"\n[*] Patch 'frida-agent' with '{CUSTOM_NAME}-agent' recursively...")
    patch_strings = ["frida-agent-", "\"agent\" / \"frida-agent.", "\'frida-agent\'", "\"frida-agent\"",
                     "get_frida_agent_", "\'FridaAgent\'"]
    for patch_string in patch_strings:
        replace_strings_in_files(custom_dir,
                                 patch_string,
                                 patch_string.replace("Frida", capitalize_first_lower_char(
                                     CUSTOM_NAME)) if "Frida" in patch_string else
                                 patch_string.replace("frida", CUSTOM_NAME))

    # Patch the original file back, which has incorrectly patched strings.
    wrong_patch_strings = [f'{CUSTOM_NAME}-agent-x86.symbols', f'{CUSTOM_NAME}-agent-android.version']
    for wrong_patch_string in wrong_patch_strings:
        replace_strings_in_files(custom_dir,
                                 wrong_patch_string,
                                 wrong_patch_string.replace(CUSTOM_NAME, 'frida'))

    # frida-server patch
    print(f"\n[*] Patch 'frida-server' with '{CUSTOM_NAME}-server' recursively...")
    frida_server_meson_path = os.path.join(custom_dir, "subprojects/frida-core/server/meson.build")
    patch_strings = ["frida-server-raw", "\'frida-server\'", "\"frida-server\"", "frida-server-universal"]
    for patch_string in patch_strings:
        replace_strings_in_files(frida_server_meson_path,
                                 patch_string,
                                 patch_string.replace("frida", CUSTOM_NAME))

    frida_core_compat_build_path = os.path.join(custom_dir, "subprojects/frida-core/compat/build.py")
    patch_string = "frida-server"
    replace_strings_in_files(frida_core_compat_build_path,
                             patch_string,
                             patch_string.replace("frida", CUSTOM_NAME))

    # frida-gadget patch
    print(f"\n[*] Patch 'frida-gadget' with '{CUSTOM_NAME}-gadget' recursively...")
    patch_strings = ["\"frida-gadget\"", "\"frida-gadget-tcp", "\"frida-gadget-unix"]
    for patch_string in patch_strings:
        replace_strings_in_files(custom_dir,
                                 patch_string,
                                 patch_string.replace("frida", CUSTOM_NAME))

    frida_core_meson_path = os.path.join(custom_dir, "subprojects/frida-core/meson.build")
    patch_string = "gadget_name = 'frida-gadget' + shlib_suffix"
    replace_strings_in_files(frida_core_meson_path,
                             patch_string,
                             patch_string.replace("frida", CUSTOM_NAME))

    frida_core_compat_build_py_path = os.path.join(custom_dir, "subprojects/frida-core/compat/build.py")
    patch_string = "frida-gadget"
    replace_strings_in_files(frida_core_compat_build_py_path,
                             patch_string,
                             patch_string.replace("frida", CUSTOM_NAME))

    frida_gadget_meson_path = os.path.join(custom_dir, "subprojects/frida-core/lib/gadget/meson.build")
    patch_strings = ["frida-gadget-modulated", "libfrida-gadget-modulated", "frida-gadget-raw", "\'frida-gadget\'",
                     "frida-gadget-universal", "FridaGadget.dylib"]
    for patch_string in patch_strings:
        replace_strings_in_files(frida_gadget_meson_path,
                                 patch_string,
                                 patch_string.replace("Frida", capitalize_first_lower_char(
                                     CUSTOM_NAME)) if "Frida" in patch_string else
                                 patch_string.replace("frida", CUSTOM_NAME))

    # gum-js-loop patch
    print(f"\n[*] Patch 'gum-js-loop' with '{CUSTOM_NAME}-js-loop' recursively...")
    patch_string = "\"gum-js-loop\""
    replace_strings_in_files(custom_dir,
                             patch_string,
                             patch_string.replace("gum", CUSTOM_NAME))

    # pool-frida patch
    print(f"\n[*] Patch 'pool-frida' with 'pool-{CUSTOM_NAME}' recursively...")
    patch_string = "g_set_prgname (\"frida\");"
    replace_strings_in_files(custom_dir,
                             patch_string,
                             patch_string.replace("frida", CUSTOM_NAME))

    # No libsystem_c.dylib hooking
    print(f"\n[*] Patch not to hook libc function")
    # frida/subprojects/frida-core/lib/payload/exit-monitor.vala
    exit_monitor_path = os.path.join(custom_dir, "subprojects/frida-core/lib/payload/exit-monitor.vala")
    patch_string = "interceptor.attach"
    replace_strings_in_files(exit_monitor_path,
                             patch_string,
                             "// " + patch_string)

    # frida/subprojects/frida-gum/gum/backend-posix/gumexceptor-posix.c
    gumexceptor_posix_path = os.path.join(custom_dir, "subprojects/frida-gum/gum/backend-posix/gumexceptor-posix.c")
    gumexceptor_posix_patch_strings = ["gum_interceptor_replace",
                                       "gum_exceptor_backend_replacement_signal, self, NULL);",
                                       "gum_exceptor_backend_replacement_sigaction, self, NULL);"]
    for patch_string in gumexceptor_posix_patch_strings:
        replace_strings_in_files(gumexceptor_posix_path,
                                 patch_string,
                                 "// " + patch_string)

    # No removing cloaked threads
    print(f"\n[*] Patch thread-suspend-monitor for iOS")
    # frida/subprojects/frida-core/lib/payload/thread-suspend-monitor.vala
    thread_suspend_monitor_path = os.path.join(custom_dir,
                                               "subprojects/frida-core/lib/payload/thread-suspend-monitor.vala")
    patch_string = "interceptor.replace ((void *) task_threads"
    replace_strings_in_files(thread_suspend_monitor_path,
                             patch_string,
                             "// " + patch_string)

    # # Need to patch?? frida/subprojects/frida-core/lib/payload/unwind-sitter.vala
    # print(f"\n[*] Patch unwind-sitter.vala for iOS")
    # unwind_sitter_path = os.path.join(custom_dir, "subprojects/frida-core/lib/payload/unwind-sitter.vala")
    # patch_string = "interceptor.replace"
    # replace_strings_in_files(unwind_sitter_path,
    #                          patch_string,
    #                          "// " + patch_string)

    # Perform the first build
    for build_dir in build_dirs:
        print(f"\n[*] First build for {build_dir.rsplit('/')[-1]}")
        build(build_dir)

    # frida_agent_main patch
    print(f"\n[*] Patch 'frida_agent_main' with '{CUSTOM_NAME}_agent_main' recursively...")
    patch_string = "frida_agent_main"
    replace_strings_in_files(custom_dir,
                             patch_string,
                             patch_string.replace("frida", CUSTOM_NAME))

    # Second build after patching
    for build_dir in build_dirs:
        print(f"\n[*] Second build for {build_dir.rsplit('/')[-1]}")
        build(build_dir)
        if 'ios-' in build_dir:
            # No patch gumexceptor-posix.c to prevent the crash issue when scanning the memory
            for patch_string in gumexceptor_posix_patch_strings:
                replace_strings_in_files(gumexceptor_posix_path,
                                         "// " + patch_string,
                                         patch_string)

            # /usr/lib/frida/frida-agent.dylib path patch
            print(f"\n[*] Patch 'usr/lib/frida' with 'usr/lib/{CUSTOM_NAME}' recursively...")
            patch_string = "usr/lib/frida"
            replace_strings_in_files(custom_dir,
                                     patch_string,
                                     patch_string.replace("frida", CUSTOM_NAME))

            # Third build for iOS
            print(f"\n[*] Third build for {build_dir.rsplit('/')[-1]}")
            build(build_dir)

    # Patch gmain, gdbus, pool-spawner
    gmain = bytes.fromhex('67 6d 61 69 6e 00')
    amain = bytes.fromhex('61 6d 61 69 6e 00')

    gdbus = bytes.fromhex('67 64 62 75 73 00')
    gdbug = bytes.fromhex('67 64 62 75 67 00')

    pool_spawner = bytes.fromhex('70 6f 6f 6c 2d 73 70 61 77 6e 65 72 00')
    pool_spoiler = bytes.fromhex('70 6f 6f 6c 2d 73 70 6f 69 6c 65 72 00')

    patch_list = [os.path.join(build_dir, f"subprojects/frida-core/server/{CUSTOM_NAME}-server") for build_dir in
                  build_dirs] + \
                 [os.path.join(build_dir,
                               f"subprojects/frida-core/lib/agent/{CUSTOM_NAME}-agent.dylib") for build_dir in
                  build_dirs] + \
                 [os.path.join(build_dir,
                               f"subprojects/frida-core/lib/gadget/{CUSTOM_NAME}-gadget.dylib") for build_dir in
                  build_dirs]

    for file_path in patch_list:
        # Open the binary file for reading and writing
        with open(file_path, 'rb+') as f:
            print(f"\n[*] gmain, gdbus, pool-spawner patch for {file_path}")
            # Read the entire file content
            content = f.read()
            patched_content = content.replace(gmain, amain)
            patched_content = patched_content.replace(gdbus, gdbug)
            patched_content = patched_content.replace(pool_spawner, pool_spoiler)

            f.seek(0)
            f.write(patched_content)
            f.truncate()

    # Patch packcage-server-fruity.sh for iOS
    print(f"\n[*] Patch package-server-fruity.sh")
    # frida/subprojects/frida-core/tools/package-server-fruity.sh
    package_server_fruity_path = os.path.join(custom_dir, "subprojects/frida-core/tools/package-server-fruity.sh")
    patch_strings = ["frida-server", "frida-agent.dylib"]
    for patch_string in patch_strings:
        replace_strings_in_files(package_server_fruity_path,
                                 patch_string,
                                 patch_string.replace("frida", f"{CUSTOM_NAME}"))

    # Get frida version
    frida_version_py = os.path.join(custom_dir, "releng/frida_version.py")
    result = subprocess.run(['python3', frida_version_py], capture_output=True, text=True)
    frida_version = result.stdout.strip()

    # Rename
    for file_path in patch_list:
        if 'ios-' in file_path:
            try:
                if '-server' in file_path:
                    shutil.move(file_path, ios_assets_frida_server_dir)
                elif '-agent.dylib' in file_path:
                    shutil.move(file_path, ios_assets_frida_agent_dir)
                else:
                    shutil.move(file_path, ios_assets_dir)
            except Exception as e:
                print(f"[!] Error {file_path}: {e}")

    # Create universal frida-server for iOS
    # lipo, codesign frida-server, codesign frida-agent.dylib
    for arch in ["arm64", "arm64e"]:
        run_command(f"lipo {CUSTOM_NAME}-server -thin {arch} -output {CUSTOM_NAME}-server-{arch}",
                    cwd=f"{ios_assets_dir}/usr/bin")
        run_command(f"codesign -f -s \"-\" --preserve-metadata=entitlements {CUSTOM_NAME}-server-{arch}",
                    cwd=f"{ios_assets_dir}/usr/bin")
    run_command(f"codesign -f -s \"-\" {CUSTOM_NAME}-agent.dylib", cwd=f"{ios_assets_dir}/usr/lib/{CUSTOM_NAME}")
    # Codesign frida-gadget.dylib
    run_command(f"codesign -f -s \"-\" {CUSTOM_NAME}-gadget.dylib", cwd=f"{ios_assets_dir}")

    # Make fat macho
    print("\n[*] Making fat macho...")
    mkfatmacho_py = os.path.join(custom_dir, "releng/mkfatmacho.py")
    result = subprocess.run(["python3", mkfatmacho_py, f"{CUSTOM_NAME}-server", f"{CUSTOM_NAME}-server-arm64",
                             f"{CUSTOM_NAME}-server-arm64e"], capture_output=True, text=True,
                            cwd=f"{ios_assets_dir}/usr/bin")
    if result.returncode == 0:
        for arch in ["arm64", "arm64e"]:
            os.remove(f"{ios_assets_dir}/usr/bin/{CUSTOM_NAME}-server-{arch}")
    else:
        print("Error while making fat macho")
        sys.exit(1)

    # deb packaging
    print("\n[*] Packaging deb...")
    os.environ['FRIDA_VERSION'] = frida_version
    deb_packaging_arch = "iphoneos-arm64"
    run_command(
        f"{custom_dir}/subprojects/frida-core/tools/package-server-fruity.sh {deb_packaging_arch} {ios_assets_dir} {CUSTOM_NAME}_{os.environ['FRIDA_VERSION']}_{deb_packaging_arch}.deb", cwd=assets_dir)

    print(f"\n[*] Building of {CUSTOM_NAME} completed. The output is in the assets directory")


if __name__ == "__main__":
    main()

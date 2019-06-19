//
//  main.swift
//  iemu_prep
//
//  Created by Lakr Aream on 2019/6/19.
//  Copyright © 2019 Lakr Aream. All rights reserved.
//

import Foundation

print(" ")
print("-> iQemu iPsw iPreparer")
print("-> Created by Lakr Aream on 2019/6/19.")
print(" ")
print("-> Usage [ipsw file] [where to put it]")
print(" ")
print("-> For more information, please visit: https://alephsecurity.com/2019/06/17/xnu-qemu-arm64-1/")

print("!!! Please unmount any un-mount-able disk before continue.")
print("!!! Please unmount any un-mount-able disk before continue.")
print("!!! Please unmount any un-mount-able disk before continue.")
print("Press enter to go.")
_ = readLine()

func shell(_ command: String) -> String {
    let task = Process()
    task.launchPath = "/bin/bash"
    task.arguments = ["-c", command]
    
    let pipe = Pipe()
    task.standardOutput = pipe
    task.launch()
    
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    let output: String = (NSString(data: data, encoding: String.Encoding.utf8.rawValue) as String?) ?? ""
    
    return output
}

func sizeForLocalFilePath(filePath:String) -> UInt64 {
    do {
        let fileAttributes = try FileManager.default.attributesOfItem(atPath: filePath)
        if let fileSize = fileAttributes[FileAttributeKey.size]  {
            return (fileSize as! NSNumber).uint64Value
        } else {
            print("Failed to get a size attribute from path: \(filePath)")
        }
    } catch {
        print("Failed to get file attributes for local path: \(filePath) with error: \(error)")
    }
    return 0
}

func exitWithError(str: String) {
    print(" ")
    print(str)
    print(" ")
    exit(-1)
}

if shell("whoami") != "root\n" {
    print(shell("whoami"))
    exitWithError(str: "Operation not permitted.")
}

if CommandLine.arguments.count < 3 {
    exitWithError(str: "Arguments count error.")
}

if !FileManager.default.fileExists(atPath: CommandLine.arguments[1]) {
    exitWithError(str: "File not exists at " + CommandLine.arguments[1])
}

let sourceFile = CommandLine.arguments[1]
var targertFile = CommandLine.arguments[2]
if targertFile.hasSuffix("/") {
    targertFile = targertFile.dropLast().description
}

let tempFile = shell("cd ~; pwd").dropLast().description + "/iQemuiPswiPreparer-" + UUID().uuidString

var shellCommandTemp = ""
var cdFirst = "cd " + tempFile + ";"

print("[*] Checking output dir if is clean...")
if FileManager.default.fileExists(atPath: targertFile) {
    exitWithError(str: "File exists at target dir.")
}
shellCommandTemp = "mkdir -p " + targertFile
_ = shell(shellCommandTemp)

try! FileManager.default.createDirectory(atPath: tempFile, withIntermediateDirectories: true, attributes: nil)
print("[*] Temp files are put into " + tempFile)

print("[+] Extracting files from ipsw...")
shellCommandTemp = cdFirst + "unzip " + sourceFile
_ = shell(shellCommandTemp)

print("[+] Gettting files from GitHub...")
shellCommandTemp = cdFirst + "git clone https://github.com/alephsecurity/xnu-qemu-arm64-scripts.git"
_ = shell(shellCommandTemp)
shellCommandTemp = cdFirst + "git clone https://github.com/jakeajames/rootlessJB.git"
_ = shell(shellCommandTemp)

print("[+] Doing stuffs with kernel...")
var kernels = [String]()
for kernel in (try FileManager.default.contentsOfDirectory(atPath: tempFile)) where kernel.hasPrefix("kernelcache.") {
    kernels.append(kernel)
}
var target_kernel = String()
if kernels.count == 0 {
    exitWithError(str: "No kernel cache was found!")
} else if kernels.count == 1 {
    target_kernel = kernels.first!
} else {
    print("-> Multiple kernel caches was found.")
    var index = 0
    for item in kernels {
        print("--- " + index.description + " -- " + item)
        index += 1
    }
    print("-> Which one would you like to use? (0..." + kernels.count.description + ")")
    var flag = false
    while !flag {
        let read = readLine()
        if Int(read ?? "") ?? -1 >= 0 && Int(read ?? "") ?? 666 < kernels.count {
            target_kernel = kernels[Int(read!)!]
            print("-> You have selected to use " + target_kernel)
            flag = true
        } else {
            print("Invalid input. Press ctrl+z to exit, and clean temp files yourself.")
        }
    }
}
shellCommandTemp = cdFirst + "python xnu-qemu-arm64-scripts/asn1kerneldecode.py " + target_kernel + " kernel.asn1"
_ = shell(shellCommandTemp)
shellCommandTemp = cdFirst + "python xnu-qemu-arm64-scripts/decompress_lzss.py kernel.asn1 kernel.fout"
_ = shell(shellCommandTemp)
shellCommandTemp = cdFirst + "python xnu-qemu-arm64-scripts/kernelcompressedextractmonitor.py kernel.asn1 secure_monitor.fout"
_ = shell(shellCommandTemp)

print("[+] Doing stuffs with DeviceTree...")
var device_trees = [String]()
for device_tree in (try FileManager.default.contentsOfDirectory(atPath: tempFile + "/Firmware/all_flash/")) where device_tree.hasPrefix("DeviceTree.") {
    device_trees.append(device_tree)
}
var target_device_tree = String()
if device_trees.count == 0 {
    exitWithError(str: "No kernel cache was found!")
} else if device_trees.count == 1 {
    target_device_tree = device_trees.first!
} else {
    print("-> Multiple device trees was found.")
    var index = 0
    for item in device_trees {
        print("--- " + index.description + " -- " + item)
        index += 1
    }
    print("-> Which one would you like to use? (0..." + (device_trees.count - 1).description + ")")
    var flag = false
    while !flag {
        let read = readLine()
        if Int(read ?? "") ?? -1 >= 0 && Int(read ?? "") ?? 666 < device_trees.count {
            target_device_tree = device_trees[Int(read!)!]
            print("-> You have selected to use " + target_device_tree)
            flag = true
        } else {
            print("Invalid input. Press ctrl+z to exit, and clean temp files yourself.")
        }
    }
}
shellCommandTemp = cdFirst + "python xnu-qemu-arm64-scripts/asn1dtredecode.py Firmware/all_flash/" + target_device_tree + " device_tree.01"
_ = shell(shellCommandTemp)
shellCommandTemp = cdFirst + "python xnu-qemu-arm64-scripts/read_device_tree.py device_tree.01 device_tree.fout"
_ = shell(shellCommandTemp)

print("[+] Preparing boot images...")
var images = [String]()
var fileSystemImage = String()
judge: for image in (try FileManager.default.contentsOfDirectory(atPath: tempFile)) where image.hasSuffix(".dmg") {
    let full = tempFile + "/" + image
    if sizeForLocalFilePath(filePath: full) > 1073741824 {
        fileSystemImage = image
        continue judge
    }
    images.append(image)
}
var target_image = String()
if images.count == 0 {
    exitWithError(str: "No boot images was found!")
} else if images.count == 1 {
    target_image = images.first!
} else {
    print("-> Multiple boot image was found.")
    var index = 0
    for item in images {
        let full = tempFile + "/" + item
        let fileSizeMB = Int(sizeForLocalFilePath(filePath: full) / 1024 / 1024).description
        print("--- " + index.description + " -- " + item + " --- " + fileSizeMB + " MB")
        index += 1
    }
    print("-> Which one would you like to use? (0..." + (images.count - 1).description + ")")
    print("-> If you have no idea, the bigger one might be it.")
    var flag = false
    while !flag {
        let read = readLine()
        if Int(read ?? "") ?? -1 >= 0 && Int(read ?? "") ?? 666 < images.count {
            target_image = images[Int(read!)!]
            print("-> You have selected to use " + target_image)
            flag = true
        } else {
            print("Invalid input. Press ctrl+z to exit, and clean temp files yourself.")
        }
    }
}
shellCommandTemp = cdFirst + "python xnu-qemu-arm64-scripts/asn1rdskdecode.py " + target_image + " boot_image.fout"
print(shell(shellCommandTemp))
shellCommandTemp = cdFirst + "hdiutil resize -size 1.88G -imagekey diskimage-class=CRawDiskImage boot_image.fout"
print(shell(shellCommandTemp))
shellCommandTemp = cdFirst + "hdiutil attach -imagekey diskimage-class=CRawDiskImage boot_image.fout"
let readBootImage = shell(shellCommandTemp)
print(readBootImage)
var image_name = String()
for line in readBootImage.split(separator: "\n") where line.contains("/Volumes/") {
    image_name = line.split(separator: "/").last?.description ?? ""
}
shellCommandTemp = cdFirst + "diskutil enableownership /Volumes/" + image_name
print(shell(shellCommandTemp))

print("[+] Preparing file system image...")
shellCommandTemp = cdFirst + "hdiutil attach " + fileSystemImage
let readFSImageInfo = shell(shellCommandTemp)
print(readFSImageInfo)
var fs_image_name = String()
for line in readFSImageInfo.split(separator: "\n") where line.contains("/Volumes/") {
    fs_image_name = line.split(separator: "/").last?.description ?? ""
}

print("[*] Checking mount point status before going to something wrong...")
if !FileManager.default.fileExists(atPath: "/Volumes/" + image_name) || image_name == "" {
    exitWithError(str: "Failed to mount boot image.")
} else {
    print("[*] Boot image mounted at /Volumes/" + image_name)
}
if !FileManager.default.fileExists(atPath: "/Volumes/" + fs_image_name) || fs_image_name == ""  {
    exitWithError(str: "Failed to mount fs image.")
} else {
    print("[*] File system image mounted at /Volumes/" + fs_image_name)
}

print("[+] Preparing dyld...")
shellCommandTemp = "mkdir -p /Volumes/" + image_name + "/System/Library/Caches/com.apple.dyld/"
_ = shell(shellCommandTemp)
shellCommandTemp = "cp /Volumes/" + fs_image_name + "/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64 /Volumes/" + image_name + "/System/Library/Caches/com.apple.dyld/"
_ = shell(shellCommandTemp)
shellCommandTemp = "chown root:wheel /Volumes/" + image_name + "/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64"
_ = shell(shellCommandTemp)

print("[+] Doing magic for LaunchDaemons..")
shellCommandTemp = "mkdir /Volumes/" + image_name + "/System/Library/dlbak"
_ = shell(shellCommandTemp)
shellCommandTemp = "mv /Volumes/" + image_name + "/System/Library/LaunchDaemons/* /Volumes/" + image_name + "/System/Library/dlbak/"
_ = shell(shellCommandTemp)
let daemon_str = """
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>EnablePressuredExit</key>
<false/>
<key>Label</key>
<string>com.apple.bash</string>
<key>POSIXSpawnType</key>
<string>Interactive</string>
<key>ProgramArguments</key>
<array>
<string>/iosbinpack64/bin/bash</string>
</array>
<key>RunAtLoad</key>
<true/>
<key>StandardErrorPath</key>
<string>/dev/console</string>
<key>StandardInPath</key>
<string>/dev/console</string>
<key>StandardOutPath</key>
<string>/dev/console</string>
<key>Umask</key>
<integer>0</integer>
<key>UserName</key>
<string>root</string>
</dict>
</plist>
"""
try! daemon_str.write(toFile: tempFile + "/com.apple.bash.plist", atomically: true, encoding: .utf8)
shellCommandTemp = cdFirst + "cp com.apple.bash.plist /Volumes/" + image_name + "/System/Library/LaunchDaemons/"
_ = shell(shellCommandTemp)
shellCommandTemp = "chown root:wheel /Volumes/" + image_name + "/System/Library/LaunchDaemons/"
_ = shell(shellCommandTemp)

print("[+] Preparing iOS bin pack...")
shellCommandTemp = cdFirst + "cd rootlessJB/rootlessJB/bootstrap/tars/; tar xvf iosbinpack.tar; cp -R iosbinpack64 /Volumes/" + image_name + "/"
_ = shell(shellCommandTemp)

print("[+] Will generate trust cache...")
shellCommandTemp = "for filename in $(find /Volumes/" + image_name + "/iosbinpack64 -type f); do /usr/local/bin/jtool --sig --ent $filename; done | grep CDHash | cut -d' ' -f6 | cut -c 1-40"
let read_hash = shell(shellCommandTemp)
var hashes = String()
for line in read_hash.split(separator: "\n") {
    if line.description.count == "ebe945ddbb4dbeb1ee9624e6ba1932d2ec61cfde".count && !line.description.contains(" ") && !line.description.contains("-") {
        hashes += line.description + "\n"
    }
}
try! hashes.write(toFile: tempFile + "/hashes", atomically: true, encoding: .utf8)
shellCommandTemp = cdFirst + "python xnu-qemu-arm64-scripts/create_trustcache.py hashes static_tc.fout"
_ = shell(shellCommandTemp)

print("[+] Cleaning mount points before we continue...")
shellCommandTemp = "hdiutil detach /Volumes/" + image_name
_ = shell(shellCommandTemp)
shellCommandTemp = "hdiutil detach /Volumes/" + fs_image_name
_ = shell(shellCommandTemp)

print("[+] Time to have our files ready.")
for out in (try FileManager.default.contentsOfDirectory(atPath: tempFile)) where out.hasSuffix(".fout") {
    print("-> Copying output file " + out)
    shellCommandTemp = cdFirst + "cp -r " + out + " " + targertFile + "/"
    _ = shell(shellCommandTemp)
}

print("[+] Removing temp files...")
shellCommandTemp = "rm -rf " + tempFile
_ = shell(shellCommandTemp)

print("[+] Generating bootstrap command...")

print(" ")
print("--> Boot with:     * Current qemu only support iPhone 6s Plus. Parying my friend!")
print(" ")
print("qemu-system-aarch64 -M iPhone6splus-n66-s8000,kernel-filename=kernel.fout,dtb-filename=device_tree.fout,secmon-filename=secure_monitor.fout,ramdisk-filename=boot_image.fout,tc-filename=static_tc.fout,kern-cmd-args=\"debug=0x8 kextlog=0xfff cpus=1 rd=md0 serial=2\" -cpu max -m 6G -serial mon:stdio")
print(" ")

print("[*] Job done.")

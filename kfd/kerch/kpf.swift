//
//  kpf.swift
//  kfd
//
//  Created by mizole on 2023/09/22.
//

import Foundation
import KernelPatchfinder
import SwiftMachO

func findKernel() -> String? {
    print("Searching for running kernel...")
    guard let active = try? String(contentsOfFile: "/private/preboot/active") else {
        print("Unable to get active preboot")
        return nil
    }
    print("Found active preboot: \(active)")
    let kernelPath = "/private/preboot/\(active)/System/Library/Caches/com.apple.kernelcaches/kernelcache"
    guard FileManager.default.fileExists(atPath: kernelPath) else {
        print("Unable to find kernel (tried \(kernelPath))")
        return nil
    }
    return kernelPath
}

func getKernel() -> String? {
    guard let rawKernelCachePath = findKernel() else {
        print("err")
        return nil
    }
    print(rawKernelCachePath)
    let tmpKernelCachePath = "/tmp/kernelcache"
    let tmpKernelPath = "/tmp/kernel"
    
    try? FileManager.default.removeItem(atPath: tmpKernelCachePath)
    try? FileManager.default.removeItem(atPath: tmpKernelPath)
    
    do {
        try FileManager.default.copyItem(at: URL(fileURLWithPath: rawKernelCachePath),
                                           to: URL(fileURLWithPath: tmpKernelCachePath))
    } catch {
        print("Unable to copy kernelcache to tmp folder")
        return nil
    }
    
    guard let asn1Parser = Asn1Parser(url: URL(fileURLWithPath: tmpKernelCachePath)) else {
        print("Unable to open kernelcache")
        return nil
    }
    if asn1Parser.isIMG4() {
        guard asn1Parser.unwrapIMG4() else {
            print("Unable to unwrap kernelCache container")
            return nil
        }
    }
    guard asn1Parser.isIM4P() else {
        print("kernelCache is not valid format")
        return nil
    }
    guard asn1Parser.parseIM4P(outputPath: tmpKernelPath) else {
        print("Unable to extract kernelcache")
        return nil
    }
    
    try? FileManager.default.removeItem(atPath: tmpKernelCachePath)
    guard FileManager.default.fileExists(atPath: tmpKernelPath) else {
        print("ASN1 parser succeeded but kernel not present???")
        return nil
    }
    
    let kernelURL = URL(fileURLWithPath: tmpKernelPath)
    
    if let kernelInfo = unpackFat(url: kernelURL) {
        print("FAT binary detected. Extracting")
        
        guard kernelInfo.count >= 0 else {
            print("Kernel is FAT but no slices")
            return nil
        }
        
        let offset = kernelInfo[0].offset
        let size = kernelInfo[0].size
        
        guard let fileHandle = try? FileHandle(forReadingFrom: kernelURL) else {
            return nil
        }
        
        defer { try? fileHandle.close() }
        
        let fileSize = fileHandle.seekToEndOfFile()
        fileHandle.seek(toFileOffset: 0)
        
        guard offset + size <= fileSize else {
            print("Slice extends past end of file")
            return nil
        }
        
        fileHandle.seek(toFileOffset: UInt64(offset))
        
        let outKernelURL = URL(fileURLWithPath: tmpKernelPath + "-thin")
        guard FileManager.default.createFile(atPath: tmpKernelPath + "-thin", contents: nil),
              let outFileHandle = try? FileHandle(forWritingTo: outKernelURL) else {
            print("Unable to open output handle")
            return nil
        }
        defer { try? outFileHandle.close() }
        
        do {
            
            var writtenBytes = UInt32(0)
            while (writtenBytes < size){
                let chunkBytes = min(16384, size - writtenBytes)
                
                autoreleasepool {
                    let chunk = fileHandle.readData(ofLength: Int(chunkBytes))
                    outFileHandle.write(chunk)
                }
                writtenBytes += chunkBytes
            }
            
            try FileManager.default.removeItem(at: URL(fileURLWithPath: tmpKernelPath))
            try FileManager.default.moveItem(at: URL(fileURLWithPath: tmpKernelPath + "-thin"),
                                         to: URL(fileURLWithPath: tmpKernelPath))
            print("FAT extracted successfully")
        } catch {
            print("Error saving slice from FAT binary")
            return nil
        }
    }
    
    return tmpKernelPath
}

func fugu15_kpf() {
    do {
        let kerneldata = try Data(contentsOf: URL(fileURLWithPath: getKernel().unsafelyUnwrapped))
        let kernelmacho = try MachO(fromData: kerneldata, okToLoadFAT: false)
        guard let pf = KernelPatchfinder.init(kernel: kernelmacho) else {
            print("pf nil")
            return
        }
        KernelPatchfinder.self
        //print(String(pf.allproc ?? 0x0, radix: 16))
    } catch {
        print("error")
    }
}

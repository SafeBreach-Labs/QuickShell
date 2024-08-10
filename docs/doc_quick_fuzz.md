# quick_fuzz

A fuzzer for Quick Share on Windows: Each fuzzing iteration sends a sequence of OfflineFrames, simulating a complete transfer session.

## Build
Run:
```cmd
bazel build //quick_fuzz:fuzzing_harness
bazel build //quick_fuzz:quick_share_fuzzing_patches
```
The DLLs will be created in `./bazel-bin/quick_fuzz`

## Requirement
As far as we tried, DynamoRIO does not support recent Windows versions. We have tested and successfully ran this fuzzer on the following Windows versions:
  * Windows 10 20h2
  * Windows 10 22h2

Once you install one of them, make sure you disable updates. 

## Usage

* `fuzzing_harness.dll` should be used as an argument for afl-fuzz.exe
* `quick_share_fuzzing_patches.dll` should be injected into the Quick Share app that is being fuzzed. Inside the vulnerable version of the Quick Share app that we uploaded to this repo, you'll find a file called `nearby_sharing_dart_fuzzer_patches.dll` in addition to `nearby_sharing_dart.dll`. The `nearby_sharing_dart_fuzzer_patches.dll` file is a modified version of `nearby_sharing_dart.dll` that is dependent on `quick_share_fuzzing_patches.dll`. Therefore, once you compiled `quick_share_fuzzing_patches.dll` you can do these two simple actions in order to have the Quick Share app running with an injected `quick_share_fuzzing_patches.dll`:
  * Copy `quick_share_fuzzing_patches.dll` into the root folder of the vulnerable Quick Share app
  * Rename `nearby_sharing_dart_fuzzer_patches.dll` to `nearby_sharing_dart.dll` 

In addition to these DLLs, you'll need to have WinAFL as the fuzzing framework. We needed to perform a small patch in WinAFL's code in order for it to work with our harness and libprotobuf-mutator. You can either run the [`clone_and_patch_winafl.bat`](/quick_fuzz/winafl_clone_and_patch/clone_and_patch_winafl.bat) script that we created and then follow WinAFL's instructions for compilation yourself. Or you can use the precompiled version of WinAFL that we uploaded to this repo at [precompiled_patched_winafl.zip](/quick_fuzz/precompiled_patched_winafl.zip). Note that you'll have to download DynamoRIO version 10.92.19896, since `afl-fuzz.exe` needs it in order to run. You can download it from [here](https://github.com/DynamoRIO/dynamorio/releases/download/cronbuild-10.92.19896/DynamoRIO-Windows-10.92.19896.zip)

### Usage of afl-fuzz with our harness:
You should refer to WinAFL's documentation in order to fully understand `afl-fuzz.exe`'s parameters

```cmd
.\afl-fuzz.exe -i <CORPUS_FOLDER> -o <OUTPUT_FOLDER> -l <PATH_TO_fuzzing_harness.dll> -D <PATH_TO_DYNAMORIO_BIN64> -t 100000 -- -persistence_mode in_app -coverage_module nearby_sharing_dart.dll -target_module nearby_sharing_dart.dll -target_offset <target_function_offset> -- <PATH_TO_NEARBYSHARE.EXE>
```

The target function for this fuzzer is called `BasePcpHandler::OnIncomingConnection`. In the vulnerable version of the Quick Share app that we uploaded to this repo, this function's address is `0x4DA800`

### Example usage
```cmd
.\afl-fuzz.exe -i .\corpus -o .\output -l .\fuzzing_harness.dll -D .\DynamoRIO-Windows-10.92.19896\bin64 -t 100000 -- -persistence_mode in_app -coverage_module nearby_sharing_dart.dll -target_module nearby_sharing_dart.dll -target_offset 0x4DA800 -- .\VulnerableQuickShare\nearby_share.exe
```
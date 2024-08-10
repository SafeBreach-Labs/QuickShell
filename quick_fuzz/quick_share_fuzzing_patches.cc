// dllmain.cpp : Defines the entry point for the DLL application.

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "user32.lib")
#include <winsock2.h>
#include <Windows.h>

#define EXTERN_DLL_EXPORT extern "C" __declspec(dllexport)

#define NOP_OP              0x90

CHAR* IMAGE_BASE;


void patch_bytes_with_nops(CHAR* address_to_patch, DWORD bytes_len) {
    // A function for patching bytes at address `address_to_patch` with NOP op codes.
    DWORD fl_old_protect = 0;

    VirtualProtect(address_to_patch, bytes_len, PAGE_EXECUTE_READWRITE, &fl_old_protect);
    memset(address_to_patch, NOP_OP, bytes_len);
}

void patch_bytes(CHAR* address_to_patch, char* bytes_to_patch, DWORD bytes_len) {
    // A function for patching bytes at address `address_to_patch` with bytes_to_patch op codes.
    DWORD fl_old_protect = 0;

    VirtualProtect(address_to_patch, bytes_len, PAGE_EXECUTE_READWRITE, &fl_old_protect);
    memmove(address_to_patch, bytes_to_patch, bytes_len);

}

void enable_auto_accept() {
    /*
    Enable Auto-Accepting feature, for more info check out:
    https://source.chromium.org/chromium/chromium/src/+/main:chrome/browser/nearby_sharing/nearby_sharing_service_impl.cc;l=3644;drc=76ee012c8192bdfd62f59e451cc5ecd8aaf6e3c1
    */

    DWORD FIRST_IF_OFFSET = 0x41995E;
    patch_bytes_with_nops(IMAGE_BASE + FIRST_IF_OFFSET, 15);
}


void enable_fast_sending() {
    DWORD sleep_500_ms_offset = 0x4A8920;
    DWORD stop_advertising = 0x497682;

    patch_bytes_with_nops(IMAGE_BASE + sleep_500_ms_offset, 5);
    patch_bytes_with_nops(IMAGE_BASE + stop_advertising, 3);
}


EXTERN_DLL_EXPORT BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        IMAGE_BASE = (CHAR*)GetModuleHandleA("nearby_sharing_dart.dll");
        if (!IMAGE_BASE) {
            MessageBoxA(0, "Failed to load nearby_sharing_dart.dll", 0, 0);
        }

        enable_auto_accept();
        // This will make Quick Share much faster in receiving files, however during fuzzing, this creates many unreproducible crashes
        // enable_fast_sending();

        break;
    }

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;

}
/*
 * IAT hooking for Windows.
 *
 * More IAT/EAT hooking methods at
 * https://gist.github.com/denikson/93ea22c1f4e79e68466a26cbfc58af05
 */

#ifndef HOOK_H
#define HOOK_H

#include "../util/util.h"
#include <windows.h>

// PE format uses RVAs (Relative Virtual Addresses) to save addresses relative
// to the base of the module More info:
// https://en.wikibooks.org/wiki/X86_Disassembly/Windows_Executable_Files#Relative_Virtual_Addressing_(RVA)
//
// This helper macro converts the saved RVA to a fully valid pointer to the data
// in the PE file
#define RVA2PTR(t, base, rva) ((t)(((PCHAR)(base)) + (rva)))

/**
 * @brief Hooks the given function through the Import Address Table.
 * This is a simplified version that doesn't does lookup directly in the
 * initialized IAT.
 * This is usable to hook system DLLs like kernel32.dll assuming the process
 * wasn't already hooked.
 *
 * @param dll Module to hook
 * @param target_dll Name of the target DLL to search in the IAT
 * @param target_function Address of the target function to hook
 * @param detour_function Address of the detour function
 * @return bool_t TRUE if successful, otherwise FALSE
 */
static bool_t iat_hook(void *dll, char const *target_dll, void *target_function,
                       void *detour_function) {
    IMAGE_DOS_HEADER *mz = (PIMAGE_DOS_HEADER)dll;

    IMAGE_NT_HEADERS *nt = RVA2PTR(PIMAGE_NT_HEADERS, mz, mz->e_lfanew);

    IMAGE_IMPORT_DESCRIPTOR *imports =
        RVA2PTR(IMAGE_IMPORT_DESCRIPTOR *, mz,
                nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
                    .VirtualAddress);

    for (int i = 0; imports[i].Characteristics; i++) {
        char *name = RVA2PTR(char *, mz, imports[i].Name);

        if (lstrcmpiA(name, target_dll) != 0)
            continue;

        void **thunk = RVA2PTR(void **, mz, imports[i].FirstThunk);

        for (; *thunk; thunk++) {
            void *import = *thunk;

            if (import != target_function)
                continue;

            DWORD old_state;
            if (!VirtualProtect(thunk, sizeof(void *), PAGE_READWRITE,
                                &old_state))
                return FALSE;

            *thunk = (void *)detour_function;

            VirtualProtect(thunk, sizeof(void *), old_state, &old_state);

            return TRUE;
        }
    }

    return FALSE;
}

/**
 * @brief Hooks the given function through the Import Address Table by matching
 * resolved function address in any imported DLL.
 *
 * Useful when the same WinAPI can be imported from kernel32, kernelbase or
 * api-ms-* forwarding libraries depending on toolchain/OS.
 */
static bool_t iat_hook_any(void *dll, void *target_function,
                           void *detour_function) {
    IMAGE_DOS_HEADER *mz = (PIMAGE_DOS_HEADER)dll;

    IMAGE_NT_HEADERS *nt = RVA2PTR(PIMAGE_NT_HEADERS, mz, mz->e_lfanew);

    IMAGE_IMPORT_DESCRIPTOR *imports =
        RVA2PTR(IMAGE_IMPORT_DESCRIPTOR *, mz,
                nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
                    .VirtualAddress);

    for (int i = 0; imports[i].Characteristics; i++) {
        void **thunk = RVA2PTR(void **, mz, imports[i].FirstThunk);

        for (; *thunk; thunk++) {
            void *import = *thunk;

            if (import != target_function)
                continue;

            DWORD old_state;
            if (!VirtualProtect(thunk, sizeof(void *), PAGE_READWRITE,
                                &old_state))
                return FALSE;

            *thunk = (void *)detour_function;

            VirtualProtect(thunk, sizeof(void *), old_state, &old_state);

            return TRUE;
        }
    }

    return FALSE;
}

/**
 * @brief Checks if DLL name matches one of target names (case-insensitive).
 */
static bool_t iat_dll_name_matches(char const *name,
                                   char const *const *target_dlls,
                                   size_t target_dll_count) {
    for (size_t i = 0; i < target_dll_count; i++) {
        if (lstrcmpiA(name, target_dlls[i]) == 0)
            return TRUE;
    }
    return FALSE;
}

/**
 * @brief Hooks function by imported symbol name in one of the specified DLLs.
 *
 * Compared to iat_hook, this implementation:
 *  - matches by imported function name instead of function address,
 *  - can search multiple possible import DLL names (kernel32/kernelbase/api-ms),
 *  - can optionally return the original function pointer.
 */
static bool_t iat_hook_by_name(void *dll, char const *const *target_dlls,
                               size_t target_dll_count,
                               char const *target_function_name,
                               void *detour_function,
                               void **original_function) {
    IMAGE_DOS_HEADER *mz = (PIMAGE_DOS_HEADER)dll;
    IMAGE_NT_HEADERS *nt = RVA2PTR(PIMAGE_NT_HEADERS, mz, mz->e_lfanew);

    IMAGE_IMPORT_DESCRIPTOR *imports =
        RVA2PTR(IMAGE_IMPORT_DESCRIPTOR *, mz,
                nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
                    .VirtualAddress);

    for (int i = 0; imports[i].Characteristics; i++) {
        char *name = RVA2PTR(char *, mz, imports[i].Name);

        if (!iat_dll_name_matches(name, target_dlls, target_dll_count))
            continue;

        IMAGE_THUNK_DATA *thunk =
            RVA2PTR(IMAGE_THUNK_DATA *, mz, imports[i].FirstThunk);

        IMAGE_THUNK_DATA *lookup_thunk = thunk;
        if (imports[i].OriginalFirstThunk) {
            lookup_thunk =
                RVA2PTR(IMAGE_THUNK_DATA *, mz, imports[i].OriginalFirstThunk);
        }

        for (; thunk->u1.Function; thunk++, lookup_thunk++) {
            if (IMAGE_SNAP_BY_ORDINAL(lookup_thunk->u1.Ordinal))
                continue;

            IMAGE_IMPORT_BY_NAME *import_by_name =
                RVA2PTR(IMAGE_IMPORT_BY_NAME *, mz,
                        lookup_thunk->u1.AddressOfData);

            if (!import_by_name)
                continue;

            if (lstrcmpA((char const *)import_by_name->Name,
                         target_function_name) != 0)
                continue;

            DWORD old_state;
            if (!VirtualProtect(thunk, sizeof(void *), PAGE_READWRITE,
                                &old_state)) {
                return FALSE;
            }

            if (original_function)
                *original_function = (void *)thunk->u1.Function;

            thunk->u1.Function = (ULONG_PTR)detour_function;

            VirtualProtect(thunk, sizeof(void *), old_state, &old_state);
            return TRUE;
        }
    }

    return FALSE;
}

#endif
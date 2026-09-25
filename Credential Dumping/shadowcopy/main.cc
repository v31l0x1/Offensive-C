#include <windows.h>
#include <stdio.h>
#include <vss.h>
#include <vswriter.h>
#include <vsbackup.h>

HRESULT create_shadow(PCWSTR volume, PWSTR *deviceObject)
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

int main()
{
    PCWSTR volume = L"C:\\";
    PWSTR deviceObject = NULL;

    HRESULT result = create_shadow(volume, &deviceObject);
    if (SUCCEEDED(result) && deviceObject)
    {
        wprintf(L"[+] Shadow copy created successfully: %ws\n", deviceObject);
    }
}

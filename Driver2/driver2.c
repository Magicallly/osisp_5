#include <ntddk.h>
#include <wdf.h>
#include <wdm.h>
#include <ntstrsafe.h>
#include "wrapper.h"

//provides information about a registry value that was requested 
RTL_QUERY_REGISTRY_TABLE queryTrackedProcessFilename[2], queryLogFilename[2];
UNICODE_STRING trackedProcessFilename, logFilename;
LARGE_INTEGER cookie;

NTSYSAPI PUCHAR NTAPI PsGetProcessImageFileName(_In_ PEPROCESS Process);
EX_CALLBACK_FUNCTION RegistryCallback;
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD DeviceAdd;
EVT_WDF_DRIVER_UNLOAD Unload;

NTSTATUS GetRegistryValue(PUNICODE_STRING path, wchar_t* key, RTL_QUERY_REGISTRY_TABLE* query, PUNICODE_STRING data) {
    RtlZeroMemory(query, sizeof(RTL_QUERY_REGISTRY_TABLE) * 2);

    data->Buffer = NULL;
    data->MaximumLength = 0;
    data->Length = 0;

    query->Name = key;
    query->Flags = RTL_QUERY_REGISTRY_DIRECT;
    query->EntryContext = data;

    return RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, path->Buffer, query, NULL, NULL);
}

void WriteOperationToFile(UNICODE_STRING operation, UNICODE_STRING processName) {
    OBJECT_ATTRIBUTES objAttr;
    HANDLE hFile;
    NTSTATUS ntstatus;
    IO_STATUS_BLOCK ioStatusBlock;
    CHAR buffer[100];
    size_t cb;

    InitializeObjectAttributes(&objAttr, &logFilename, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    ntstatus = ZwCreateFile(
        &hFile,
        FILE_APPEND_DATA,
        &objAttr,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OPEN_IF,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );

    if (NT_SUCCESS(ntstatus)) {
        ntstatus = RtlStringCbPrintfA(buffer, sizeof(buffer), "[%wZ] %wZ\r\n", processName, operation);
        if (NT_SUCCESS(ntstatus)) {
            ntstatus = RtlStringCbLengthA(buffer, sizeof(buffer), &cb);
            if (NT_SUCCESS(ntstatus)) {
                ntstatus = ZwWriteFile(hFile, NULL, NULL, NULL, &ioStatusBlock,
                    buffer, (ULONG)cb, NULL, NULL);
            }
        }
        ZwClose(hFile);
    }
}

void LogOperation(REG_NOTIFY_CLASS operationClass, UNICODE_STRING processName) {
    UNICODE_STRING operation;

    switch (operationClass)
    {
    case RegNtPostSetInformationKey:
        RtlInitUnicodeString(&operation, L"Set information key");
        break;
    case RegNtPostSetValueKey:
        RtlInitUnicodeString(&operation, L"Set value key");
        break;
    case RegNtPostDeleteValueKey:
        RtlInitUnicodeString(&operation, L"Delete value key");
        break;
    case RegNtPostDeleteKey:
        RtlInitUnicodeString(&operation, L"Delete key");
        break;
    case RegNtPostRenameKey:
        RtlInitUnicodeString(&operation, L"Rename key");
        break;
    case RegNtPostCreateKeyEx:
        RtlInitUnicodeString(&operation, L"Create key");
        break;
    case RegNtPostSaveKey:
        RtlInitUnicodeString(&operation, L"Save key");
        break;
    default:
        return;
    }

    WriteOperationToFile(operation, processName);
}


NTSTATUS RegistryCallback(PVOID CallbackContext, PVOID Argument1, PVOID Argument2)
{
    UNREFERENCED_PARAMETER(CallbackContext);
    UNREFERENCED_PARAMETER(Argument2);

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return STATUS_INVALID_DEVICE_STATE;

    HANDLE handle = PsGetCurrentProcessId();
    PEPROCESS Process;
    PsLookupProcessById(handle, &Process);

    PCHAR processName = (PCHAR)PsGetProcessImageFileName(Process);
    ANSI_STRING ansiName;
    RtlInitAnsiString(&ansiName, processName);

    UNICODE_STRING unicodeName;
    RtlInitUnicodeString(&unicodeName, L"");
    RtlAnsiStringToUnicodeString(&unicodeName, &ansiName, TRUE);

    if (RtlCompareUnicodeString(&unicodeName, &trackedProcessFilename, FALSE) == 0)
    {
        LogOperation((REG_NOTIFY_CLASS)(ULONG_PTR)Argument1, unicodeName);
    }

    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    GetRegistryValue(RegistryPath, L"TrackedProcess", queryTrackedProcessFilename, &trackedProcessFilename);
    GetRegistryValue(RegistryPath, L"LogFile", queryLogFilename, &logFilename);

    NTSTATUS status = STATUS_SUCCESS;

    WDF_DRIVER_CONFIG config;
    WDF_DRIVER_CONFIG_INIT(&config, DeviceAdd);
    config.EvtDriverUnload = Unload;

    status = WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, WDF_NO_HANDLE);

    UNICODE_STRING altitude;
    RtlInitUnicodeString(&altitude, L"100000");

    CmRegisterCallbackEx(RegistryCallback, &altitude, DriverObject, NULL, &cookie, NULL);
    return status;
}

NTSTATUS DeviceAdd(_In_ WDFDRIVER Driver, _Inout_ PWDFDEVICE_INIT DeviceInit)
{
    UNREFERENCED_PARAMETER(Driver);
    NTSTATUS status;
    WDFDEVICE hDevice;
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Kmdf_Driver: DeviceAdd\n");
    status = WdfDeviceCreate(&DeviceInit,
        WDF_NO_OBJECT_ATTRIBUTES,
        &hDevice
    );
    return status;
}

VOID Unload(IN WDFDRIVER Driver)
{
    UNREFERENCED_PARAMETER(Driver);
    //unregisters a RegistryCallback routine that a CmRegisterCallback or CmRegisterCallbackEx routine previously registered.
    CmUnRegisterCallback(cookie);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Unload\n");
}
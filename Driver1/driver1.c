#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include "wrapper.h"

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD KmdfDriverEvtDeviceAdd;
EVT_WDF_DRIVER_UNLOAD Unload;

RTL_QUERY_REGISTRY_TABLE queryXFileName[2];
RTL_QUERY_REGISTRY_TABLE queryYFileName[2];
UNICODE_STRING XProcess;
UNICODE_STRING YProcess;


VOID NotifyRoutine(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create);

//Retrieves the name of the executable file for the specified process.
//you must use NTSYSAPI for the importing executable to access the DLL's public data symbols and objects
NTSYSAPI PUCHAR NTAPI PsGetProcessImageFileName(_In_ PEPROCESS Process);

void GetRegistryValue(PUNICODE_STRING path, wchar_t* key, RTL_QUERY_REGISTRY_TABLE* query, PUNICODE_STRING data) {
    NTSTATUS regStatus = 0;
    WCHAR* regPath = path->Buffer;

    RtlZeroMemory(query, sizeof(RTL_QUERY_REGISTRY_TABLE) * 2);

    data->Buffer = NULL;
    data->MaximumLength = 0;
    data->Length = 0;

    // Pointer to a table of one or more value names and subkey names in which the caller is interested
    query[0].Name = key;
    //RTL_QUERY_REGISTRY_DIRECT	The QueryRoutine member is not used (and must be NULL)
    query[0].Flags = RTL_QUERY_REGISTRY_DIRECT;
    query[0].EntryContext = data;

    //allows the caller to query several values from the registry subtree with a single call.
    //RTL_REGISTRY_ABSOLUTE	Path is an absolute registry path.
    //RtlQueryRegistryValues returns an NTSTATUS code
    regStatus = RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, regPath, query, NULL, NULL);
}

NTSTATUS WriteToFile(UNICODE_STRING processName) {

    UNICODE_STRING     uniName;
    OBJECT_ATTRIBUTES  objAttr;

    RtlInitUnicodeString(&uniName, L"\\DosDevices\\C:\\out1.txt");
    InitializeObjectAttributes(&objAttr, &uniName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, //Specifies that the handle can only be accessed in kernel mode.
        NULL, NULL);

    HANDLE Hfile;
    NTSTATUS ntstatus;
    //A driver sets an IRP's I/O status block to indicate the final status of an I/O request,
    //before calling IoCompleteRequest for the IRP.
    IO_STATUS_BLOCK    ioStatusBlock;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return STATUS_INVALID_DEVICE_STATE;

    ntstatus = ZwCreateFile(&Hfile,
        FILE_APPEND_DATA | SYNCHRONIZE,
        &objAttr, &ioStatusBlock, NULL,
        FILE_ATTRIBUTE_NORMAL,
        0,                              //drivers set ShareAccess to zero, which gives the caller exclusive access to the open file.
        FILE_OPEN_IF,                   
        FILE_SYNCHRONOUS_IO_NONALERT,  //All operations on the file are performed synchronously.Waits in the system that synchronize I / O queuing and completion are not subject to alerts.
        NULL, 0); //For device and intermediate drivers, these parameters must be a NULL pointer and zero

#define  BUFFER_SIZE 50
    CHAR     buffer[BUFFER_SIZE];
    size_t  cb;

    if (NT_SUCCESS(ntstatus)) {
        ntstatus = RtlStringCbPrintfA(buffer, sizeof(buffer), "Process [%wZ] was detected\r\n", processName);
        if (NT_SUCCESS(ntstatus)) {
            ntstatus = RtlStringCbLengthA(buffer, sizeof(buffer), &cb);
            if (NT_SUCCESS(ntstatus)) {
                ntstatus = ZwWriteFile(Hfile, NULL, NULL, NULL, &ioStatusBlock,
                    buffer, (ULONG)cb, NULL, NULL);
            }
        }
        ZwClose(Hfile);
    }
    return ntstatus;
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT     DriverObject,
    _In_ PUNICODE_STRING    RegistryPath
)
{
    //PDRIVER_OBJECT - each driver object represents the image of a loaded kernel-mode driver. 
    //A pointer to the driver object is an input parameter to a driver's DriverEntry, AddDevice,
    //and optional Reinitialize routines and to its Unload routine, if any.
    //RegistryPath - A pointer to a UNICODE_STRING structure that contains the registry path string
    //that the driver received as input to its DriverEntry routine.
    GetRegistryValue(RegistryPath, L"XProcess", queryXFileName, &XProcess);
    GetRegistryValue(RegistryPath, L"YProcess", queryYFileName, &YProcess);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "X Process: %wZ\n", &XProcess);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Y Process: %wZ\n", &YProcess);

    NTSTATUS status = STATUS_SUCCESS;

    WDF_DRIVER_CONFIG config;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "KmdfHelloWorld: DriverEntry\n");

    WDF_DRIVER_CONFIG_INIT(&config,
        KmdfDriverEvtDeviceAdd  //event callback function performs device initialization operations when the Plug and Play (PnP) manager reports the existence of a device.
    );
    config.EvtDriverUnload = Unload; //event callback function performs operations that must take place before the driver is unloaded.

    PsSetCreateProcessNotifyRoutine((PCREATE_PROCESS_NOTIFY_ROUTINE)NotifyRoutine, FALSE); //adds a driver-supplied callback routine to,
                                                                                            //or removes it from, a list of routines to be called
                                                                                            //whenever a process is created or deleted.

    status = WdfDriverCreate(DriverObject,
        RegistryPath,
        WDF_NO_OBJECT_ATTRIBUTES,
        &config,
        WDF_NO_HANDLE
    );
    return status;
}

VOID NotifyRoutine(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create) {
    UNREFERENCED_PARAMETER(ParentId);
    //structure is an opaque data structure used internally by the operating system
    PEPROCESS Process;
    if (PsLookupProcessById(ProcessId, &Process) != STATUS_INVALID_PARAMETER)
    {
        PCHAR processName = (PCHAR)PsGetProcessImageFileName(Process);
        ANSI_STRING ansiName;
        RtlInitAnsiString(&ansiName, processName);

        UNICODE_STRING unicodeName;
        RtlAnsiStringToUnicodeString(&unicodeName, &ansiName, TRUE);
        if (RtlCompareUnicodeString(&unicodeName, &XProcess, FALSE) == 0) {
            if (Create) {
                WriteToFile(unicodeName);
                UNICODE_STRING eventName = RTL_CONSTANT_STRING(L"\\BaseNamedObjects\\CreateEvent");
                HANDLE eventHandle;
                //creates or opens a named notification event used to notify that an event has occurred.
                PKEVENT createProcessEvent = IoCreateNotificationEvent(&eventName, &eventHandle);
                //sets an event object to a signaled state if the event was not already signaled
                //and returns the previous state of the event object.
                KeSetEvent(createProcessEvent, 0, FALSE);
                //sets an event to a not-signaled state.
                KeClearEvent(createProcessEvent);
            }
            else {
                UNICODE_STRING eventName = RTL_CONSTANT_STRING(L"\\BaseNamedObjects\\StopEvent");
                HANDLE eventHandle;
                PKEVENT createProcessEvent = IoCreateNotificationEvent(&eventName, &eventHandle);
                KeSetEvent(createProcessEvent, 0, FALSE);
                KeClearEvent(createProcessEvent);
            }
        }
    }
}

NTSTATUS
KmdfDriverEvtDeviceAdd(
    _In_    WDFDRIVER       Driver,
    _Inout_ PWDFDEVICE_INIT DeviceInit
)
{
    UNREFERENCED_PARAMETER(Driver);
    NTSTATUS status;
    WDFDEVICE hDevice;
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Kmdf_Driver: DeviceAdd\n");
    //The WdfDeviceCreate method creates a framework device object.
    status = WdfDeviceCreate(&DeviceInit,
        WDF_NO_OBJECT_ATTRIBUTES,
        &hDevice
    );
    return status;
}

VOID Unload(IN WDFDRIVER Driver)
{
    UNREFERENCED_PARAMETER(Driver);
     //delete callback routine for create
    PsSetCreateProcessNotifyRoutine((PCREATE_PROCESS_NOTIFY_ROUTINE)NotifyRoutine, TRUE);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "KmdfHelloWorld: Unload\n");
}
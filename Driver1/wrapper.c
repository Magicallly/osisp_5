#include <ntifs.h>
#include "wrapper.h"

int PsLookupProcessById(HANDLE ProcessId, PEPROCESS* Process) {

    return PsLookupProcessByProcessId(ProcessId, Process);
}
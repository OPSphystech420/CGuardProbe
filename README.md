# CGuardProbe Memory Scanner and Manipulator

## Overview

CGuardProbe - memory engine designed for iOS and macOS platforms that leverages the Mach API to perform memory scanning and manipulation tasks. It offers capability to scan, search, read, write, allocate, deallocate memory in a target process, providing powerful tools for debugging, reverse engineering, or enhancing the capabilities of applications through dynamic memory analysis.


---
## Requirements

- macOS/iOS
- Mach API && Mach-O
- c++1x
- #include "CGuardMemory/CGPMemory.h"

## What's new
Added functions
- ChangeMemoryProtection
- VMTHook 
- RebindSymbol
- RebindSymbols
- RemapLibrary
- ParseIDAPattern
- ScanPattern
- ScanIDAPattern

## Features
```cpp
AddrRange SearchRange = (AddrRange){0x100000000, 0x300000000};
static vector<void*> Addr;
```
Initialize the memory engine with the task port of the target process
```cpp
CGPMemoryEngine Engine = CGPMemoryEngine(mach_task_self());
```
Get base address by simply passing lib name into this function
```cpp
uintptr_t ImageBase = Engine.GetImageBase("MainLib"); 
```
- **Memory Scanning and Searching:** Search memory regions for specific patterns or data, use CGP search types.
```cpp
// Scan float value
float Search = 3566.004f;
Engine.CGPScanMemory(SearchRange, &Search, CGP_Search_Type_Float);
// Search nearby
float SearchNearby = 0.267f;
Engine.CGPNearBySearch(0x100, &SearchNearby, CGP_Search_Type_Float);
// Get all values
Addr = Engine.GetAllResults();

// Scan int value
int Search = 728949301;
Engine.CGPScanMemory(SearchRange, &Search, CGP_Search_Type_SInt);
// Get 40 values
Addr = Engine.GetResults(40);
```
- **Reading/Writing Memory:** Directly read from or write to specific memory addresses.
```cpp
// Write to address
long WriteAddress = 0x1abc;
char newData[] = {0x01, 0x02, 0x03, 0x04}; 
Engine.CGPWriteMemory(WriteAddress, newData, sizeof(newData));

// Scan and Write
double ChangeValue = 12.5249042791403535;

// Scan double value
if (Addr.size() == 0) {
    double Search = 12.6664287277627762;
    Engine.CGPScanMemory(SearchRange, &Search, CGP_Search_Type_Double);
    // Get 80 values
    Addr = Engine.GetResults(80);
}

// Write to address
for (int i = 0; i < Addr.size(); i++) {
  Engine.CGPWriteMemory((long)Addr[i], &ChangeValue, CGP_Search_Type_Double);
}

// Read
unsigned long long readAddress = 0x1abc;
size_t dataLength = 4;

void* data = Engine.CGPReadMemory(readAddress, dataLength);
if (data) {
    // Process data
    free(data);
}

```
- **Memory Allocation/Deallocation:** Manage memory dynamically within a target process.
```cpp
size_t allocSize = 1024; // size of memory to allocate
void* allocatedMemory = Engine.CGPAllocateMemory(allocSize);

// use allocated memory...

memoryEngine.CGPDeallocateMemory(allocatedMemory, allocSize);
```

- **Memory Protection:** Modify the protection attributes of memory regions.
```cpp
void* protectAddress = allocatedMemory; // previously allocated memory
size_t protectSize = 1024;
Engine.CGPProtectMemory(protectAddress, protectSize, VM_PROT_READ | VM_PROT_WRITE);
```
- **Address Querying:** Retrieve detailed information about memory regions.
```cpp
kern_return_t kr = Engine.CGPQueryMemory(address, &size, &protection, &inheritance);
```

## Contributing

You are welcome to change and do whatever you want with this code

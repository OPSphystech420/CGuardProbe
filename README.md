# CGuardProbe Memory Scanner and Manipulator

## Overview

CGuardProbe is a comprehensive library designed for iOS and macOS platforms that leverages the Mach API to perform advanced memory scanning and manipulation tasks. It offers developers the capability to scan, read, write, allocate, and deallocate memory in a target process, providing powerful tools for debugging, reverse engineering, or enhancing the capabilities of applications through dynamic memory analysis.
---
## Features

- **Memory Scanning:** Search memory regions for specific patterns or data.
- **Reading/Writing Memory:** Directly read from or write to specific memory addresses.
- **Memory Allocation/Deallocation:** Manage memory dynamically within a target process.
- **Memory Protection:** Modify the protection attributes of memory regions.
- **Address Querying:** Retrieve detailed information about memory regions.

## Requirements

- macOS/iOS
- Mach API && Mach-O
- c++1x
- #include "CGuardMemory/CGPMemory.h"

## Usage

### Initializing the Memory Engine

Before performing any operations, initialize the memory engine with the task port of the target process:

```cpp
mach_port_t target_task; // Assume you have obtained task port of the target process
CGPMemoryEngine memoryEngine(target_task);
```

### Scanning Memory for Specific Data

Scan for a specific pattern in a predefined address range:

```cpp
AddrRange searchRange = {0x1000, 0x2000}; // Define the memory range
char targetData[] = {0x90, 0x90}; // Data to search for

memoryEngine.CGPScanMemory(searchRange, targetData, sizeof(targetData));

auto results = memoryEngine.getAllResults();
for (void* address : results) {
    printf("Found at address: %p\n", address);
}
```

### Reading Memory

Read data from a specific memory address:

```cpp
unsigned long long readAddress = 0x1abc; // Specify the address
size_t dataLength = 4; // Number of bytes to read

void* data = memoryEngine.CGPReadMemory(readAddress, dataLength);
if (data) {
    // Process your data
    free(data); // Free the allocated buffer after usage
}
```

### Writing to Memory

Modify the contents of a specific memory address:

```cpp
long writeAddress = 0x1abc; // Specify the address
char newData[] = {0x01, 0x02, 0x03, 0x04}; // New data to write
memoryEngine.CGPWriteMemory(writeAddress, newData, sizeof(newData));
```

### Allocating and Deallocating Memory

Allocate and then deallocate memory within the target process:

```cpp
size_t allocSize = 1024; // Size of memory to allocate
void* allocatedMemory = memoryEngine.CGPAllocateMemory(allocSize);

// Optionally use the allocated memory...

memoryEngine.CGPDeallocateMemory(allocatedMemory, allocSize);
```

### Protecting Memory

Change the protection of a memory region:

```cpp
void* protectAddress = allocatedMemory; // Use previously allocated memory
size_t protectSize = 1024;
memoryEngine.CGPProtectMemory(protectAddress, protectSize, VM_PROT_READ | VM_PROT_WRITE);
```

## Contributing

You are welcome to change and do whatever you want with this code

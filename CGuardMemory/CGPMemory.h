//
//  CGPMemory.h
//  CGuardProbe
//
//  Made by OPSphystech420 on 2024/5/17
//

#ifndef CGPMemory_h
#define CGPMemory_h

#include <mach-o/dyld.h>
#include <mach/mach.h>

#include <sys/mman.h>
#include <unistd.h> 

#include <iostream>

#include <cstdint> 
#include <cstring>

#include <stdio.h>

#include <algorithm>
#include <vector>

#define CGP_Search_Type_ULong 8
#define CGP_Search_Type_Double 8
#define CGP_Search_Type_SLong 8
#define CGP_Search_Type_Float 4
#define CGP_Search_Type_UInt 4
#define CGP_Search_Type_SInt 4
#define CGP_Search_Type_UShort 2
#define CGP_Search_Type_SShort 2
#define CGP_Search_Type_UByte 1
#define CGP_Search_Type_SByte 1

using namespace std;

typedef struct _result_region {
    mach_vm_address_t region_base;
    vector<uint32_t> slide;
} result_region;

typedef struct _result {
    vector<result_region*> resultBuffer;
    int count;
} Result;

typedef struct _addrRange {
    uint64_t start;
    uint64_t end;
} AddrRange;

typedef struct _image {
    vector<uint64_t> base;
    vector<uint64_t> end;
} ImagePtr;

class CGPMemoryEngine {
public:
    uintptr_t getImageBase(const std::string& imageName);

    CGPMemoryEngine(mach_port_t task);
    ~CGPMemoryEngine(void);
    
    void CGPScanMemory(AddrRange range, void* target, size_t len);
    void CGPNearBySearch(int range, void *target, size_t len);
    bool CGPSearchByAddress(unsigned long long address, void* target, size_t len);
    
    void *CGPReadMemory(unsigned long long address, size_t len);
    void CGPWriteMemory(long address, void *target, int len);
    
    vector<void*> getAllResults();
    vector<void*> getResults(int count);
    
    void* CGPAllocateMemory(size_t size);
    void CGPDeallocateMemory(void* address, size_t size);
    
    kern_return_t CGPProtectMemory(void* address, size_t size, vm_prot_t protection);
    kern_return_t CGPQueryMemory(void* address, vm_size_t* size, vm_prot_t* protection, vm_inherit_t* inheritance);
    
    bool changeMemoryProtection(uintptr_t address, size_t size, int protection);
    
    template<int Index>
    void hookVMTFunction(uintptr_t classInstance, uintptr_t newFunction, uintptr_t& originalFunction);

    bool rebindSymbol(const char* symbolName, void* newFunction, void** originalFunction);
    bool rebindSymbols(
        const std::vector<std::tuple<const char*, void*, void**>>& symbols,
        const std::function<bool(const char*)>& condition = nullptr,
        const std::function<void(const char*)>& onFailure = nullptr
    );
    
private:
    mach_port_t task;
    Result *result;
    
    void ResultDeallocate(Result *result);
    Result* ResultAllocate(void);
};


#endif /* CGPMemory_h */

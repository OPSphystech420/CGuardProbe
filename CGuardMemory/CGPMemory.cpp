/* * * * * * * * * * * * * * * * * * *
 * * CGPMemory.cpp * * * * * * * * * *
 * * CGuardProbe (And More!) * * * * *
 * * * * * * * * * * * * * * * * * * *
 * * Made by OPSphystech420  * * * * *
 * * Contributor ZarakiDev 2024 (c)  *
 * * * * * * * * * * * * * * * * * * */

#include "CGPMemory.h"

#pragma mark - CGPMemoryEngine Implementation -

CGPMemoryEngine::CGPMemoryEngine(mach_port_t task)
    : task_(task), result_(AllocateResult()), pageSize_(static_cast<size_t>(sysconf(_SC_PAGESIZE)))
{
    if (!result_) {
        SetError(CGPErrorCode::Allocation_Fail, "result_ : CGPMemoryEngine");
        task_ = MACH_PORT_NULL;
    }
}

CGPMemoryEngine::~CGPMemoryEngine()
{
    DeallocateResult();
}

void CGPMemoryEngine::DeallocateResult()
{
    result_.reset();
}

std::unique_ptr<Result> CGPMemoryEngine::AllocateResult()
{
    return std::make_unique<Result>();
}

void CGPMemoryEngine::ScanMemory(const AddrRange& range, const void* target, size_t len)
{
    if (!IsValid())
    {
        return;
    }

    if (!target || len == 0)
    {
        SetError(CGPErrorCode::Invalid_Argument, "target || len : ScanMemory");
        return;
    }

    vm_size_t size = range.end - range.start;
    vm_address_t address = range.start;
    kern_return_t kr;

    while (address < range.end)
    {
        vm_size_t vmsize;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        memory_object_name_t object;

        kr = vm_region_64(task_, &address, &vmsize, VM_REGION_BASIC_INFO_64,
                          reinterpret_cast<vm_region_info_t>(&info), &count, &object);
        if (kr != KERN_SUCCESS)
        {
            address += vmsize;
            continue;
        }

        auto buffer = std::make_unique< std::vector<uint8_t> >(vmsize);
        size_t bytesRead = 0;

        kr = vm_read_overwrite(task_, address, vmsize,
                               reinterpret_cast<vm_address_t>(buffer->data()), &bytesRead);
        if (kr != KERN_SUCCESS)
        {
            address += vmsize;
            continue;
        }

        if (bytesRead > vmsize)
        {
            bytesRead = vmsize;
        }

        for (size_t i = 0; i <= bytesRead - len; ++i)
        {
            if (memcmp(buffer->data() + i, target, len) == 0)
            {
                auto region = std::make_unique<ResultRegion>();
                region->region_base = address + i;
                region->slide.push_back(static_cast<uint32_t>(i));
                result_->resultBuffer.emplace_back(std::move(region));
                result_->count++;
            }
        }

        address += vmsize;
    }
}

void CGPMemoryEngine::NearBySearch(int range, const void* target, size_t len)
{
    if (!IsValid())
    {
        return;
    }

    if (range <= 0 || !target || len == 0)
    {
        SetError(CGPErrorCode::Invalid_Argument, "range || target || len : NearBySearch");
        return;
    }

    std::vector< std::unique_ptr<ResultRegion> > newResultBuffer;

    for (const auto& region : result_->resultBuffer)
    {
        vm_address_t base = region->region_base;

        for (int i = -range; i <= range; ++i)
        {
            vm_address_t address = base + i * static_cast<int>(len);

            auto readResult = ReadMemory(address, len);

            if (readResult && readResult->size() == len)
            {
                if (memcmp(readResult->data(), target, len) == 0)
                {
                    auto newRegion = std::make_unique<ResultRegion>();
                    newRegion->region_base = address;
                    newResultBuffer.emplace_back(std::move(newRegion));
                }
            }
        }
    }

    result_->resultBuffer = std::move(newResultBuffer);
    result_->count = static_cast<int>(result_->resultBuffer.size());
}

bool CGPMemoryEngine::SearchByAddress(uint64_t address, const void* target, size_t len)
{
    if (!IsValid())
    {
        return false;
    }

    if (!target || len == 0)
    {
        SetError(CGPErrorCode::Invalid_Argument, "target || len : SearchByAddress");
        return false;
    }

    auto readResult = ReadMemory(address, len);

    if (readResult && readResult->size() == len)
    {
        return (memcmp(readResult->data(), target, len) == 0);
    }

    return false;
}

std::unique_ptr< std::vector<uint8_t> > CGPMemoryEngine::ReadMemory(uint64_t address, size_t len) const
{
    if (!IsValid())
    {
        return nullptr;
    }

    if (len == 0)
    {
        SetError(CGPErrorCode::Invalid_Argument, "len == 0 : ReadMemory");
        return nullptr;
    }

    auto buffer = std::make_unique< std::vector<uint8_t> >(len);
    vm_size_t bytesRead = 0;
    kern_return_t kr = vm_read_overwrite(task_, address, len,
                                        reinterpret_cast<vm_address_t>(buffer->data()), &bytesRead);

    if (kr != KERN_SUCCESS || bytesRead != len)
    { // Error description mach_error_string(kr)
        SetError(CGPErrorCode::VMRead_Fail, "Failed to ReadMemory");
        return nullptr;
    }

    return buffer;
}

bool CGPMemoryEngine::WriteMemory(uint64_t address, const void* data, size_t len)
{
    if (!IsValid())
    {
        return false;
    }

    if (!data || len == 0)
    {
        SetError(CGPErrorCode::Invalid_Argument, "data || len : WriteMemory");
        return false;
    }

    kern_return_t kr = vm_write(task_, static_cast<vm_address_t>(address),
                                reinterpret_cast<vm_offset_t>(const_cast<void*>(data)),
                                static_cast<mach_msg_type_number_t>(len));
    if (kr != KERN_SUCCESS)
    { // Error description mach_error_string(kr)
        SetError(CGPErrorCode::VMWrite_Fail, "Failed to WriteMemory");
        return false;
    }

    return true;
}

std::vector<void*> CGPMemoryEngine::GetAllResults() const
{
    if (!IsValid())
    {
        return {};
    }

    std::vector<void*> addresses;
    addresses.reserve(result_->resultBuffer.size());

    for (const auto& region : result_->resultBuffer)
    {
        if (region)
        {
            addresses.emplace_back(reinterpret_cast<void*>(region->region_base));
        }
    }

    return addresses;
}

std::vector<void*> CGPMemoryEngine::GetResults(int count) const
{
    if (!IsValid())
    {
        return {};
    }

    std::vector<void*> addresses;

    if (count <= 0)
    {
        return addresses;
    }

    size_t actualCount = std::min(static_cast<size_t>(count), result_->resultBuffer.size());
    addresses.reserve(actualCount);

    for (size_t i = 0; i < actualCount; ++i)
    {
        if (result_->resultBuffer[i])
        {
            addresses.emplace_back(reinterpret_cast<void*>(result_->resultBuffer[i]->region_base));
        }
    }

    return addresses;
}

void* CGPMemoryEngine::AllocateMemory(size_t size)
{
    if (!IsValid())
    {
        return nullptr;
    }

    if (size == 0)
    {
        SetError(CGPErrorCode::Invalid_Argument, "size == 0 : AllocateMemory");
        return nullptr;
    }

    vm_address_t address = 0;
    kern_return_t kr = vm_allocate(task_, &address, size, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS)
    { // Error description mach_error_string(kr)
        SetError(CGPErrorCode::Allocation_Fail, "Failed to AllocateMemory");
        return nullptr;
    }

    return reinterpret_cast<void*>(address);
}

bool CGPMemoryEngine::DeallocateMemory(void* address, size_t size)
{
    if (!IsValid())
    {
        return false;
    }

    if (!address || size == 0)
    {
        SetError(CGPErrorCode::Invalid_Argument, "address || size : DeallocateMemory");
        return false;
    }

    kern_return_t kr = vm_deallocate(task_, reinterpret_cast<mach_vm_address_t>(address), size);
    if (kr != KERN_SUCCESS)
    { // Error description mach_error_string(kr)
        SetError(CGPErrorCode::VMDeallocate_Fail, "Failed to DeallocateMemory");
        return false;
    }

    return true;
}

kern_return_t CGPMemoryEngine::ProtectMemory(void* address, size_t size, vm_prot_t protection)
{
    if (!IsValid())
    {
        return KERN_INVALID_ARGUMENT;
    }

    if (!address || size == 0)
    {
        SetError(CGPErrorCode::Invalid_Argument, "address || size : ProtectMemory");
        return KERN_INVALID_ADDRESS;
    }

    kern_return_t kr = vm_protect(task_, reinterpret_cast<vm_address_t>(address), size, FALSE, protection);
    if (kr != KERN_SUCCESS)
    { // Error description mach_error_string(kr)
        SetError(CGPErrorCode::VMProtect_Fail, "Failed to ProtectMemory");
    }

    return kr;
}

kern_return_t CGPMemoryEngine::QueryMemory(void* address, vm_size_t* size, vm_prot_t* protection, vm_inherit_t* inheritance) const
{
    if (!IsValid())
    {
        return KERN_INVALID_ARGUMENT;
    }

    if (!address || !size || !protection || !inheritance)
    {
        SetError(CGPErrorCode::Invalid_Argument, "address || size || protection || inheritance : QueryMemory");
        return KERN_INVALID_ARGUMENT;
    }

    vm_address_t addr = reinterpret_cast<vm_address_t>(address);
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    memory_object_name_t object;

    kern_return_t kr = vm_region_64(task_, &addr, size, VM_REGION_BASIC_INFO_64,
                                    reinterpret_cast<vm_region_info_t>(&info), &count, &object);
    if (kr == KERN_SUCCESS)
    {
        *protection = info.protection;
        *inheritance = info.inheritance;
    }
    else
    { // Error description mach_error_string(kr)
        SetError(CGPErrorCode::VMQuery_Fail, "Failed to QueryMemory");
    }

    return kr;
}

#pragma mark - CGPMemoryScanner Implementation -

CGPMemoryScanner::CGPMemoryScanner(const std::string& binaryName, const std::string& segmentName)
    : CGPMemoryEngine(mach_task_self()), SegmentStart_(0), SegmentEnd_(0)
{
    const struct mach_header_64* header = nullptr;

    uint32_t imageCount = _dyld_image_count();

    for (uint32_t i = 0; i < imageCount; ++i)
    {
        const char* imageName = _dyld_get_image_name(i);

        if (strstr(imageName, binaryName.c_str()))
        {
            header = reinterpret_cast<const mach_header_64*>(_dyld_get_image_header(i));
            break;
        }
    }

    if (!header)
    {
        SetError(CGPErrorCode::Binary_Not_Found, "Binary not found in loaded images");
        return;
    }

    unsigned long segmentSize = 0;
    uintptr_t segmentData = reinterpret_cast<uintptr_t>(getsegmentdata(header, segmentName.c_str(), &segmentSize));

    if (!segmentData)
    {
        SetError(CGPErrorCode::Segment_Not_Found, "Segment not found in binary");
        return;
    }

    SegmentStart_ = segmentData;
    SegmentEnd_ = SegmentStart_ + segmentSize;
}

uintptr_t CGPMemoryScanner::FindDirectSig(const std::string& signature, int step) const
{
    if (!IsValid())
    {
        return 0;
    }

    uintptr_t found = FindIDAPatternFirst(signature);
    return (found != 0) ? (found + step) : 0;
}

uintptr_t CGPMemoryScanner::Find_ADRL_Sig(const std::string& signature, int step) const
{
    if (!IsValid())
    {
        return 0;
    }

    uintptr_t insnAddress = FindDirectSig(signature, step);

    if (insnAddress == 0)
    {
        return 0;
    }

    // read ADRP instruction
    auto adrpRead = ReadMemory(insnAddress, sizeof(uint32_t));

    if (!adrpRead || adrpRead->size() != sizeof(uint32_t))
    {
        return 0;
    }

    uint32_t adrpInsn = *reinterpret_cast<uint32_t*>(adrpRead->data());

    // read ADD instruction
    auto addRead = ReadMemory(insnAddress + sizeof(uint32_t), sizeof(uint32_t));

    if (!addRead || addRead->size() != sizeof(uint32_t))
    {
        return 0;
    }

    uint32_t addInsn = *reinterpret_cast<uint32_t*>(addRead->data());

    if (adrpInsn == 0 || addInsn == 0)
    {
        return 0;
    }

    int64_t adrpPcRel = 0;

    if (!DecodeADRImmediate(adrpInsn, &adrpPcRel) || adrpPcRel == 0)
    {
        return 0;
    }

    int32_t addImm12 = DecodeAddSubImmediate(addInsn);

    return (GetPageOffset(insnAddress) + adrpPcRel + addImm12);
}

uintptr_t CGPMemoryScanner::Find_ADRP_LDRSTR_Sig(const std::string& signature, int step) const
{
    if (!IsValid())
    {
        return 0;
    }

    uintptr_t insnAddress = FindDirectSig(signature, step);

    if (insnAddress == 0)
    {
        return 0;
    }

    // read ADRP instruction
    auto adrpRead = ReadMemory(insnAddress, sizeof(uint32_t));

    if (!adrpRead || adrpRead->size() != sizeof(uint32_t))
    {
        return 0;
    }

    uint32_t adrpInsn = *reinterpret_cast<uint32_t*>(adrpRead->data());

    // read LDRSTR instruction
    auto ldrStrRead = ReadMemory(insnAddress + sizeof(uint32_t), sizeof(uint32_t));

    if (!ldrStrRead || ldrStrRead->size() != sizeof(uint32_t))
    {
        return 0;
    }

    uint32_t ldrStrInsn = *reinterpret_cast<uint32_t*>(ldrStrRead->data());

    if (adrpInsn == 0 || ldrStrInsn == 0)
    {
        return 0;
    }

    int64_t adrpPcRel = 0;

    if (!DecodeADRImmediate(adrpInsn, &adrpPcRel) || adrpPcRel == 0)
    {
        return 0;
    }

    int32_t ldrStrImm12 = 0;

    if (!DecodeLDRSTRImmediate(ldrStrInsn, &ldrStrImm12))
    {
        return 0;
    }

    return (GetPageOffset(insnAddress) + adrpPcRel + ldrStrImm12);
}

uintptr_t CGPMemoryScanner::Find_LDRSTR_Sig64(const std::string& signature, int step) const
{
    if (!IsValid())
    {
        return 0;
    }

    uintptr_t insnAddress = FindDirectSig(signature, step);

    if (insnAddress == 0)
    {
        return 0;
    }

    // read LDRSTR instruction
    auto ldrStrRead = ReadMemory(insnAddress, sizeof(int32_t));
    if (!ldrStrRead || ldrStrRead->size() != sizeof(int32_t))
    {
        return 0;
    }

    int32_t ldrStrInsn = *reinterpret_cast<int32_t*>(ldrStrRead->data());

    if (ldrStrInsn == 0)
    {
        return 0;
    }

    uintptr_t imm12 = (ldrStrInsn >> 10) & 0xFFF;

    return imm12 * 8;
}

uintptr_t CGPMemoryScanner::Find_LDRSTR_Sig32(const std::string& signature, int step) const
{
    if (!IsValid())
    {
        return 0;
    }

    uintptr_t insnAddress = FindDirectSig(signature, step);

    if (insnAddress == 0)
    {
        return 0;
    }

    // read LDRSTR instruction
    auto ldrStrRead = ReadMemory(insnAddress, sizeof(int32_t));
    if (!ldrStrRead || ldrStrRead->size() != sizeof(int32_t))
    {
        return 0;
    }

    int32_t ldrStrInsn = *reinterpret_cast<int32_t*>(ldrStrRead->data());

    if (ldrStrInsn == 0)
    {
        return 0;
    }

    uint32_t imm12 = (ldrStrInsn >> 10) & 0xFFF;

    return imm12 * 8;
}

bool CGPMemoryScanner::ComparePattern(const char* data, const char* pattern, const char* mask) const
{
    while (*mask)
    {
        if (*mask == 'x' && *data != *pattern)
        {
            return false;
        }

        ++data;
        ++pattern;
        ++mask;
    }
    return true;
}

uintptr_t CGPMemoryScanner::SearchInRange(uintptr_t start, const char* pattern, const std::string& mask) const
{
    size_t scanSize = mask.length();

    if (scanSize < 1 || (start + scanSize) > SegmentEnd_)
    {
        return 0;
    }

    size_t length = SegmentEnd_ - start;

    for (size_t i = 0; i <= length - scanSize; ++i)
    {
        uintptr_t currentAddress = start + i;

        if (ComparePattern(reinterpret_cast<const char*>(currentAddress), pattern, mask.c_str()))
        {
            return currentAddress;
        }
    }

    return 0;
}

std::vector<uintptr_t> CGPMemoryScanner::FindBytesAll(const std::vector<char>& bytes, const std::string& mask) const
{
    if (!IsValid())
    {
        return {};
    }

    std::vector<uintptr_t> results;

    if (SegmentStart_ >= SegmentEnd_ || bytes.empty() || mask.empty())
    {
        return results;
    }

    if (bytes.size() != mask.size())
    {
        return results;
    }

    uintptr_t currentSearchAddress = SegmentStart_;
    size_t scanSize = mask.length();

    while (currentSearchAddress + scanSize <= SegmentEnd_)
    {
        uintptr_t found = SearchInRange(currentSearchAddress, bytes.data(), mask);

        if (found == 0) 
        {
            break;
        }

        results.emplace_back(found);
        currentSearchAddress = found + scanSize;
    }

    return results;
}

uintptr_t CGPMemoryScanner::FindBytesFirst(const std::vector<char>& bytes, const std::string& mask) const
{
    if (!IsValid())
    {
        return 0;
    }

    if (SegmentStart_ >= SegmentEnd_ || bytes.empty() || mask.empty())
    {
        return 0;
    }

    if (bytes.size() != mask.size())
    {
        return 0;
    }

    return SearchInRange(SegmentStart_, bytes.data(), mask);
}

std::vector<uintptr_t> CGPMemoryScanner::FindIDAPatternAll(const std::string& pattern) const
{
    if (!IsValid())
    {
        return {};
    }

    std::vector<uintptr_t> results;

    if (SegmentStart_ >= SegmentEnd_)
    {
        return results;
    }

    std::string mask;
    std::vector<char> bytes;

    size_t patternLen = pattern.length();

    for (size_t i = 0; i < patternLen; ++i)
    {
        if (pattern[i] == ' ')
        {
            continue;
        }

        if (pattern[i] == '?')
        {
            bytes.push_back(0);
            mask += '?';
        }
        else if (std::isxdigit(pattern[i]) && (i + 1) < patternLen && std::isxdigit(pattern[i + 1]))
        {
            std::string byteStr = pattern.substr(i, 2);
            bytes.push_back(static_cast<char>(std::stoi(byteStr, nullptr, 16)));
            mask += 'x';
            ++i; // skip next character
        }
        else
        {
            // invalid pattern character
            return results;
        }
    }

    if (bytes.empty() || mask.empty() || bytes.size() != mask.size())
    {
        return results;
    }

    return FindBytesAll(bytes, mask);
}

uintptr_t CGPMemoryScanner::FindIDAPatternFirst(const std::string& pattern) const
{
    if (!IsValid())
    {
        return 0;
    }

    if (SegmentStart_ >= SegmentEnd_)
    {
        return 0;
    }

    std::string mask;
    std::vector<char> bytes;

    size_t patternLen = pattern.length();

    for (size_t i = 0; i < patternLen; ++i)
    {
        if (pattern[i] == ' ')
        {
            continue;
        }

        if (pattern[i] == '?')
        {
            bytes.push_back(0);
            mask += '?';
        }
        else if (std::isxdigit(pattern[i]) && (i + 1) < patternLen && std::isxdigit(pattern[i + 1]))
        {
            std::string byteStr = pattern.substr(i, 2);
            bytes.push_back(static_cast<char>(std::stoi(byteStr, nullptr, 16)));
            mask += 'x';
            ++i; // skip next character
        }
        else
        {
            // invalid pattern character
            return 0;
        }
    }

    if (bytes.empty() || mask.empty() || bytes.size() != mask.size())
    {
        return 0;
    }

    return FindBytesFirst(bytes, mask);
}

uintptr_t CGPMemoryScanner::GetPageOffset(uintptr_t address) const
{
    return address & ~(pageSize_ - 1);
}

#pragma mark - CGPInstructionDecoder Implementation -

int32_t CGPInstructionDecoder::GetBit(uint32_t insn, int pos) const
{
    return (insn >> pos) & 1;
}

int32_t CGPInstructionDecoder::GetBits(uint32_t insn, int pos, int length) const
{
    return (insn >> pos) & ((1 << length) - 1);
}

bool CGPInstructionDecoder::IsADR(uint32_t insn) const
{
    return (insn & 0x9F000000) == 0x10000000;
}

bool CGPInstructionDecoder::IsADRP(uint32_t insn) const
{
    return (insn & 0x9F000000) == 0x90000000;
}

bool CGPInstructionDecoder::IsLDR(uint32_t insn) const
{
    return GetBit(insn, 22) == 1;
}

bool CGPInstructionDecoder::IsLDRSTU(uint32_t insn) const
{
    return (insn & 0x0A000000) == 0x08000000;
}

bool CGPInstructionDecoder::IsLDRSTUImm(uint32_t insn) const
{
    return (insn & 0x3B000000) == 0x39000000;
}

bool CGPInstructionDecoder::DecodeADRImmediate(uint32_t insn, int64_t* imm) const
{
    if (IsADR(insn) || IsADRP(insn))
    {
        // 21-bit immediate
        int64_t imm_val = GetBits(insn, 5, 19) << 2; // immhi
        imm_val |= GetBits(insn, 29, 2);             // immlo

        if (IsADRP(insn))
        {
            // Sign-extend the 21-bit immediate
            int64_t sign = (imm_val >> 20) & 1;
            imm_val <<= 12;

            if (sign)
            {
                imm_val |= (~0ULL) << 33;
            }

            *imm = imm_val;
        }
        else // ADR
        {
            // Sign-extend the 21-bit immediate
            if (imm_val & (1 << 20))
            {
                imm_val |= ~((1LL << 21) - 1);
            }

            *imm = imm_val;
        }

        return true;
    }

    return false;
}

bool CGPInstructionDecoder::DecodeLDRSTRImmediate(uint32_t insn, int32_t* imm12) const
{
    if (IsLDRSTUImm(insn))
    {
        *imm12 = GetBits(insn, 10, 12);

        // shift with scale value
        *imm12 <<= GetBits(insn, 30, 2); // size bits

        return true;
    }

    return false;
}

/*
*  31 30 29 28         23 22 21         10 9   5 4   0
* +--+--+--+-------------+--+-------------+-----+-----+
* |sf|op| S| 1 0 0 0 1 0 |sh|    imm12    |  Rn | Rd  |
* +--+--+--+-------------+--+-------------+-----+-----+
*
*    sf: 0 -> 32bit, 1 -> 64bit
*    op: 0 -> add  , 1 -> sub
*     S: 1 -> set flags
*    sh: 1 -> LSL imm by 12
*/

int32_t CGPInstructionDecoder::DecodeAddSubImmediate(uint32_t insn) const
{
    int32_t imm12 = GetBits(insn, 10, 12);
    bool shift = GetBit(insn, 22) == 1;

    if (shift)
    {
        imm12 <<= 12;
    }

    return imm12;
}
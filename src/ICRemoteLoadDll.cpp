/*
====================================================================================
Copyright (C) 2020 Nagisa. All Rights Reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

3. The name of the author may not be used to endorse or promote products
derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
====================================================================================
*/

#include "MindSurge.h"


typedef BOOL (WINAPI *fnGetProcessMitigationPolicy)(
    HANDLE                    hProcess,
    PROCESS_MITIGATION_POLICY MitigationPolicy,
    PVOID                     lpBuffer,
    SIZE_T                    dwLength
);

typedef BOOL (WINAPI *fnSetProcessValidCallTargets)(
    HANDLE                hProcess,
    PVOID                 VirtualAddress,
    SIZE_T                RegionSize,
    ULONG                 NumberOfOffsets,
    PCFG_CALL_TARGET_INFO OffsetInformation
);


/*
===============================================================================
    Class CMS1RemoteLoadDll
===============================================================================
*/


/**
 * Constructs a CMS1RemoteLoadDll object.
 */
MindSurge::CMS1RemoteLoadDll::CMS1RemoteLoadDll(HANDLE hRemoteProcess, const char *pszDllFileName)
{

    SetExtendedError(FuncNoError);
    m_hRemoteProcess = hRemoteProcess;
    m_pszDllFileName = pszDllFileName;
    m_iNumberOfCallTargetsInBuffer = 0;
    m_pAllocatedMemoryRegion = NULL;
    m_RemoteCfgBitmapBaseAddress = NULL;
    m_bInstanceEnabled = false;

}


/**
 * Destroys the CMS1RemoteLoadDll object.
 */
MindSurge::CMS1RemoteLoadDll::~CMS1RemoteLoadDll()
{

}



MindSurge::eMSError MindSurge::CMS1RemoteLoadDll::StagePrepRemoteLoadLibrary()
{
    eMSError funcError;

    SetExtendedError(FuncInvalidProcessHandle);
    if ((m_hRemoteProcess == NULL) || (m_hRemoteProcess == INVALID_HANDLE_VALUE))
    {
        return FuncBadParameters;
    }

    SetExtendedError(FuncInvalidDllFileName);
    if (m_pszDllFileName == nullptr)
    {
        return FuncBadParameters;
    }

    m_iDllNameLength = lstrlenA(m_pszDllFileName) + 1;
    if ((m_iDllNameLength == 1) || (m_iDllNameLength > MAX_PATH))
    {
        return FuncBadParameters;
    }


    funcError = IsTargetProcessCfgEnabled();
    if (funcError == FuncIsTargetProcessCfgEnabledFailed)
    {
        return funcError;
    }

    if (funcError == FuncFalse)
    {
        return FuncTargetProcessIsNotCfgEnabled;
    }


    funcError = GetRemoteCfgBitmapBaseAddress();
    if (funcError != FuncSuccess)
    {
        return funcError;
    }

    m_nRequestedAllocationSize = (m_iDllNameLength * 8) * 16;

    funcError = ParallelAllocateCfgBitmapStates();
    if (funcError == FuncParallelAllocationFailed)
    {
        if (GetExtendedError() == FuncVirtualQueryExApiFailed)
        {
            m_nAllocatedMemorySize = m_nRequestedAllocationSize;
        }

        RemoteCleanup();
        return funcError;
    }


    funcError = DoDllNameToCfgBitmapStatesConversion();
    if (funcError == FuncSuccess)
    {
        funcError = WriteStatesToRemoteCfgBitmap();

        free(m_pCallTargetsInformationBuffer);

        if (funcError == FuncSuccess)
        {
            m_bInstanceEnabled = true;
            return funcError;
        }
    }

    RemoteCleanup();
    return funcError;
}



MindSurge::eMSError MindSurge::CMS1RemoteLoadDll::LaunchDllOnRemoteProcess()
{

    SetExtendedError(FuncInstanceNotEnabledToOperate);

    if (m_bInstanceEnabled == false)
    {
        return FuncError;
    }

    SetExtendedError(FuncLaunchDllOnRemoteProcessFailed);

    DWORD dwThreadId;
    HANDLE hRemoteLoadLibThread = CreateRemoteThread(
        m_hRemoteProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"),
        (LPVOID)(m_RemoteCfgBitmapBaseAddress + (((ULONG_PTR)m_pAllocatedMemoryRegion >> 8) * 4)),
        0,
        &dwThreadId);

    CloseHandle(hRemoteLoadLibThread);

    if (hRemoteLoadLibThread != NULL)
    {    
        return FuncSuccess;
    }

    return FuncLaunchDllOnRemoteProcessFailed;
}




MindSurge::eMSError MindSurge::CMS1RemoteLoadDll::IsTargetProcessCfgEnabled()
{
    eMSError extendedError = FuncGetProcessMitigationPolicyNotFound;

    SetExtendedError(FuncNoError);

    fnGetProcessMitigationPolicy pfnGetProcessMitigationPolicy = (fnGetProcessMitigationPolicy)GetProcAddress(
        GetModuleHandleA("kernel32.dll"),
        "GetProcessMitigationPolicy");

    if (pfnGetProcessMitigationPolicy != NULL)
    {
        PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY ProcessCfgPolicy;

        extendedError = FuncGetProcessMitigationPolicyApiFailed;

        if (pfnGetProcessMitigationPolicy(
            m_hRemoteProcess,
            PROCESS_MITIGATION_POLICY::ProcessControlFlowGuardPolicy,
            (LPVOID)&ProcessCfgPolicy,
            sizeof(PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY)) == TRUE)
        {
            return (ProcessCfgPolicy.EnableControlFlowGuard == TRUE) ?
                FuncTrue : FuncFalse;
        }
    }
    
    SetExtendedError(extendedError);
    return FuncIsTargetProcessCfgEnabledFailed;

}



MindSurge::eMSError MindSurge::CMS1RemoteLoadDll::GetRemoteCfgBitmapBaseAddress()
{

    eMSError extendedError = FuncLdrSystemDllInitBlockNotFound;

    SetExtendedError(FuncNoError);

    ULONG_PTR pLdrSystemDllInitBlock = (ULONG_PTR)GetProcAddress(
        GetModuleHandleA("ntdll.dll"),
        "LdrSystemDllInitBlock");

    if (pLdrSystemDllInitBlock != NULL)
    {
        extendedError = FuncReadProcessMemoryApiFailed;

        SIZE_T dwNumberOfBytesRead;
        if (ReadProcessMemory(
            m_hRemoteProcess,
            (LPCVOID)(pLdrSystemDllInitBlock + 0xb0),
            (LPVOID)&m_RemoteCfgBitmapBaseAddress,
            sizeof(ULONG_PTR),
            &dwNumberOfBytesRead) == TRUE)
        {

            return FuncSuccess;
        }
    }

    SetExtendedError(extendedError);
    return FuncGetRemoteCfgBitmapBaseAddressFailed;

}



MindSurge::eMSError MindSurge::CMS1RemoteLoadDll::ParallelAllocateCfgBitmapStates()
{
    eMSError extendedError = FuncVirtualAllocExApiFailed;
    
    SetExtendedError(FuncNoError);

    LPVOID pRemoteMemRegion = VirtualAllocEx(
        m_hRemoteProcess,
        NULL,
        m_nRequestedAllocationSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READ);

    if (pRemoteMemRegion != NULL)
    {
        extendedError = FuncVirtualQueryExApiFailed;

        MEMORY_BASIC_INFORMATION MemoryBasicInformation;

        if (VirtualQueryEx(
            m_hRemoteProcess,
            pRemoteMemRegion,
            &MemoryBasicInformation,
            sizeof(MEMORY_BASIC_INFORMATION)) != 0)
        {

            m_pAllocatedMemoryRegion = pRemoteMemRegion;
            m_nAllocatedMemorySize = MemoryBasicInformation.RegionSize;

            return FuncSuccess;

        }

        VirtualFreeEx(
            m_hRemoteProcess,
            m_pAllocatedMemoryRegion,
            m_nRequestedAllocationSize,
            MEM_RELEASE);

        m_pAllocatedMemoryRegion = NULL;
    }

    SetExtendedError(extendedError);
    return FuncParallelAllocationFailed;

}



MindSurge::eMSError MindSurge::CMS1RemoteLoadDll::RemoteCleanup()
{
    eMSError extendedError = FuncAllocationPointerIsInvalid;
    SetExtendedError(FuncNoError);

    if (m_pAllocatedMemoryRegion != NULL)
    {
        extendedError = FuncVirtualFreeExFailed;
        if (VirtualFreeEx(
            m_hRemoteProcess,
            m_pAllocatedMemoryRegion,
            m_nRequestedAllocationSize,
            MEM_RELEASE) == TRUE)
        {
            return FuncSuccess;
        }
    }

    return FuncRemoteCleanupFailed;
}




MindSurge::eMSError MindSurge::CMS1RemoteLoadDll::DoDllNameToCfgBitmapStatesConversion()
{
    eMSError extendedError = FuncmallocFailed;
    SetExtendedError(FuncNoError);

    int iBufferSize = (m_iDllNameLength * 8) * sizeof(CFG_CALL_TARGET_INFO);
    m_pCallTargetsInformationBuffer = (PCFG_CALL_TARGET_INFO)malloc(iBufferSize);

    memset(m_pCallTargetsInformationBuffer, 0, iBufferSize);

    if (m_pCallTargetsInformationBuffer != nullptr)
    {
        eMSError funcError = DllFileNameToCfgCallTargetInfo();
        if (funcError == FuncSuccess)
        {
            SetExtendedError(FuncNoError);
            return funcError;
        }

        extendedError = funcError;

        free(m_pCallTargetsInformationBuffer);
    }

    SetExtendedError(extendedError);
    return FuncConversionAlgorithmFailed;

}


MindSurge::eMSError MindSurge::CMS1RemoteLoadDll::DllFileNameToCfgCallTargetInfo()
{

    SetExtendedError(FuncNoError);

    m_iNumberOfCallTargetsInBuffer = 0;

    CFG_CALL_TARGET_INFO *pCurrentInfo = m_pCallTargetsInformationBuffer;

    ULONG_PTR dwTargetOffset = 0;
    int iNumberOfCallTargets = 0;

    __try {
        for (int iCharIndex = 0; iCharIndex < m_iDllNameLength; iCharIndex++)
        {
            char cByte = m_pszDllFileName[iCharIndex];

            for (int iBitsCount = 0; iBitsCount < 4; iBitsCount++)
            {
                int state = cByte & 3;

                if (state == 2)
                {
                    return FuncFoundIllegalBitPair;
                }

                if (state != 3)
                {
                    pCurrentInfo->Flags = 0;

                    if (state == 1)
                    {
                        pCurrentInfo->Flags = CFG_CALL_TARGET_VALID;
                    }

                    pCurrentInfo->Offset = dwTargetOffset;
                    pCurrentInfo++;
                    iNumberOfCallTargets++;
                }

                dwTargetOffset = dwTargetOffset + 16;
                cByte = cByte >> 2;
            }

        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        SetExtendedError(FuncExceptionDuringConversion);
    }

    m_iNumberOfCallTargetsInBuffer = iNumberOfCallTargets;

    return FuncSuccess;
}


MindSurge::eMSError MindSurge::CMS1RemoteLoadDll::WriteStatesToRemoteCfgBitmap()
{
    eMSError extendedError = FuncSetProcessValidCallTargetsNotFound;
    SetExtendedError(FuncNoError);

    fnSetProcessValidCallTargets pfnSetProcessValidCallTargets = 
        (fnSetProcessValidCallTargets)GetProcAddress(
            GetModuleHandleA("kernelbase.dll"),
            "SetProcessValidCallTargets");

    if (pfnSetProcessValidCallTargets != NULL)
    {
        extendedError = FuncSetProcessValidCallTargetsApiFailed;

        if (pfnSetProcessValidCallTargets(
            m_hRemoteProcess,
            m_pAllocatedMemoryRegion,
            m_nAllocatedMemorySize,
            m_iNumberOfCallTargetsInBuffer,
            m_pCallTargetsInformationBuffer) == TRUE)
        {
            return FuncSuccess;
        }
    }

    SetExtendedError(extendedError);
    return FuncWriteStatesToRemoteCfgBitmapFailed;
}


MindSurge::eMSError MindSurge::CMS1RemoteLoadDll::GetExtendedError()
{
    return m_ExtendedError;
}



void MindSurge::CMS1RemoteLoadDll::SetExtendedError(eMSError extendedError)
{
    m_ExtendedError = extendedError;
}
#pragma once

#include "windows.h"

namespace MindSurge {

enum eMSError : int {
    FuncError = 0,
    FuncSuccess,
    FuncNoError,
    FuncTrue,
    FuncFalse,
    FuncUnknownError,
    FuncBadParameters,
    FuncInstanceNotEnabledToOperate,
    FuncInvalidProcessHandle,
    FuncInvalidDllFileName,
    FuncmallocFailed,
    FuncExceptionDuringConversion,
    FuncGetRemoteCfgBitmapBaseAddressFailed,
    FuncTargetProcessIsNotCfgEnabled,
    FuncVirtualAllocExApiFailed,
    FuncVirtualFreeExFailed,
    FuncVirtualQueryExApiFailed,
    FuncReadProcessMemoryApiFailed,
    FuncIsTargetProcessCfgEnabledFailed,
    FuncGetProcessMitigationPolicyNotFound,
    FuncGetProcessMitigationPolicyApiFailed,
    FuncSetProcessValidCallTargetsNotFound,
    FuncSetProcessValidCallTargetsApiFailed,
    FuncParallelAllocationFailed,
    FuncConversionAlgorithmFailed,
    FuncWriteStatesToRemoteCfgBitmapFailed,
    FuncFoundIllegalBitPair,
    FuncAllocationPointerIsInvalid,
    FuncLdrSystemDllInitBlockNotFound,
    FuncLaunchDllOnRemoteProcessFailed,
    FuncRemoteCleanupFailed,
};


class CMS1RemoteLoadDll
{

public:
    CMS1RemoteLoadDll(const HANDLE hRemoteProcess, const char *pszDllFileName);
    ~CMS1RemoteLoadDll();

    eMSError StagePrepRemoteLoadLibrary();

    eMSError LaunchDllOnRemoteProcess();

    eMSError RemoteCleanup();

    eMSError GetExtendedError();


private:
    bool                   m_bInstanceEnabled;

    eMSError               m_ExtendedError;

    HANDLE                 m_hRemoteProcess;

    const char *           m_pszDllFileName;
    int                    m_iDllNameLength;
    
    LPVOID                 m_pAllocatedMemoryRegion;
    SIZE_T                 m_nAllocatedMemorySize;
    SIZE_T                 m_nRequestedAllocationSize;
    
    PCFG_CALL_TARGET_INFO  m_pCallTargetsInformationBuffer;
    int                    m_iNumberOfCallTargetsInBuffer;

    ULONG_PTR              m_RemoteCfgBitmapBaseAddress;

    eMSError IsTargetProcessCfgEnabled();
    
    eMSError GetRemoteCfgBitmapBaseAddress();
    
    eMSError ParallelAllocateCfgBitmapStates();

    eMSError DoDllNameToCfgBitmapStatesConversion();

    eMSError DllFileNameToCfgCallTargetInfo();

    eMSError WriteStatesToRemoteCfgBitmap();

    void  SetExtendedError(eMSError extendedError);
};


} //MindSurge
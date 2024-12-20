#include "stdafx.h"

#include <stdio.h>

static const UINT16 MAX_SUBLAYER_WEIGHT				= 0xFFFF;
static const UINT32 NUM_SUBLAYER_ENTRIES_REQUESTED 	= 100;

extern "C" {

	// // EXPORT bool _cdecl WfpSubLayerIsInstalled(HANDLE engineHandle, GUID subLayerKey, UINT16* _out_Weight)
	// EXPORT FWPM_SUBLAYER0** _cdecl WfpFwpmSubLayerGetByKey(HANDLE engineHandle, GUID subLayerKey)
	// {
	// 	FWPM_SUBLAYER0 *subLayer;
	// 	DWORD result = FwpmSubLayerGetByKey0(engineHandle, &subLayerKey, &subLayer);
	// 	if (result != 0)
	// 		return NULL;
	// 	return &subLayer;
	// }
	// EXPORT FWPM_SUBLAYER0** _cdecl WfpFwpmSubLayerGetByKeyPtr(HANDLE engineHandle, GUID* subLayerKey) { return WfpFwpmSubLayerGetByKey(engineHandle, *subLayerKey); }

	// Looks for a sublayer with weight 0xFFFF (maximum possible weight).
	// If found - copies its GUID to sublayerKey
	// If not found - sets sublayerKey to zeroes
	EXPORT DWORD _cdecl  WfpFindSubLayerWithMaxWeight(HANDLE engineHandle, GUID* sublayerKey)
	{
		memset(sublayerKey, 0, sizeof(GUID));

		FWPM_SUBLAYER0** fwpmSubLayerList = NULL;
		HANDLE enumHandle = NULL;
		DWORD result = FwpmSubLayerCreateEnumHandle0(engineHandle, 0, &enumHandle), result2 = ERROR_SUCCESS;
		if (result != ERROR_SUCCESS)
			goto WfpFindSubLayerWithMaxWeight_end;

		UINT32 numEntriesReturned;
		do {
			numEntriesReturned = 0;
			result = FwpmSubLayerEnum0(engineHandle, enumHandle, NUM_SUBLAYER_ENTRIES_REQUESTED, &fwpmSubLayerList, &numEntriesReturned);
			if (result != ERROR_SUCCESS || numEntriesReturned == 0)
				goto WfpFindSubLayerWithMaxWeight_end;
			
			for (UINT32 i=0; i<numEntriesReturned; i++) {
				if (fwpmSubLayerList[i]->weight == MAX_SUBLAYER_WEIGHT) {
					memcpy_s(sublayerKey, sizeof(GUID), &(fwpmSubLayerList[i]->subLayerKey), sizeof(GUID));
					result = ERROR_SUCCESS;
					break;
				}
			}

			FwpmFreeMemory0((void**) &fwpmSubLayerList);
			fwpmSubLayerList = NULL;
		} while (numEntriesReturned > 0);

		WfpFindSubLayerWithMaxWeight_end:
		if (fwpmSubLayerList)
			FwpmFreeMemory0((void**) &fwpmSubLayerList);
		if (enumHandle)
			result2 = FwpmSubLayerDestroyEnumHandle0(engineHandle, enumHandle);
		if (result != ERROR_SUCCESS)
			return result;
		else
			return result2;
	}
	EXPORT DWORD _cdecl WfpFindSubLayerWithMaxWeightPtr(HANDLE engineHandle, GUID* sublayerKey)
	{ 
		return WfpFindSubLayerWithMaxWeight(engineHandle, sublayerKey);
	}

	EXPORT DWORD _cdecl WfpSubLayerDelete(HANDLE engineHandle, GUID subLayerKey)
	{
		return FwpmSubLayerDeleteByKey0(engineHandle, &subLayerKey);
	}
	EXPORT DWORD _cdecl WfpSubLayerDeletePtr(HANDLE engineHandle, GUID* subLayerKey) { return WfpSubLayerDelete(engineHandle, *subLayerKey); }

	EXPORT DWORD _cdecl WfpSubLayerAdd(HANDLE engineHandle, FWPM_SUBLAYER0 *subLayerStruct)
	{
		return FwpmSubLayerAdd0(engineHandle, subLayerStruct, NULL);
	}

	EXPORT FWPM_SUBLAYER0 * _cdecl FWPM_SUBLAYER0_Create(GUID subLayerKey, UINT32 weight)
	{
		FWPM_SUBLAYER0* subLayer = new FWPM_SUBLAYER0{0};
		subLayer->subLayerKey = subLayerKey;
		if (weight > 0 && weight<=0xFFFF)
			subLayer->weight = (UINT16) weight;

		return subLayer;
	}
	EXPORT FWPM_SUBLAYER0* _cdecl FWPM_SUBLAYER0_CreatePtr(GUID *subLayerKey, UINT32 weight) { return FWPM_SUBLAYER0_Create(*subLayerKey, weight); }

	EXPORT DWORD _cdecl FWPM_SUBLAYER0_SetProviderKey(FWPM_SUBLAYER0 *subLayer, GUID providerKey)
	{
		if (subLayer == NULL)
			return -1;

		subLayer->providerKey = new GUID();
		*(subLayer->providerKey) = providerKey;

		return 0;
	}
	EXPORT DWORD _cdecl FWPM_SUBLAYER0_SetProviderKeyPtr(FWPM_SUBLAYER0* subLayer, GUID *providerKey) { return FWPM_SUBLAYER0_SetProviderKey(subLayer, *providerKey); }

	EXPORT DWORD _cdecl FWPM_SUBLAYER0_SetDisplayData(FWPM_SUBLAYER0 *subLayerStruct,
		wchar_t *name, wchar_t *description)
	{
		size_t nameLen = wcslen(name);
		if (nameLen > 256)
			return -1;

		size_t descriptionLen = wcslen(description);
		if (descriptionLen > 256)
			return -1;

		subLayerStruct->displayData.name = new wchar_t[nameLen + 1];
		subLayerStruct->displayData.description = new wchar_t[descriptionLen + 1];

		wcscpy_s(subLayerStruct->displayData.name, nameLen + 1, name);
		wcscpy_s(subLayerStruct->displayData.description, descriptionLen + 1, description);

		return 0;
	}

	EXPORT void _cdecl FWPM_SUBLAYER0_SetWeight(FWPM_SUBLAYER0 *subLayerStruct, INT16 weight)
	{
		subLayerStruct->weight = weight;
	}

	EXPORT void _cdecl FWPM_SUBLAYER0_SetFlags(FWPM_SUBLAYER0 *subLayerStruct, DWORD flags)
	{
		subLayerStruct->flags = flags;		
	}

	EXPORT DWORD _cdecl FWPM_SUBLAYER0_Delete(FWPM_SUBLAYER0 *subLayerStruct)
	{
		if (subLayerStruct->providerKey != NULL)
			delete subLayerStruct->providerKey;

		if (subLayerStruct->displayData.name != NULL)
			delete[] subLayerStruct->displayData.name;

		if (subLayerStruct->displayData.description != NULL)
			delete[] subLayerStruct->displayData.description;

		delete subLayerStruct;

		return 0;
	}
}
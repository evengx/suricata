/* Copyright (C) 2018 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Jacob Masen-Smith <jacob@evengx.com>
 *
 * Isolation for WMI/COM functionality
 *
 * References:
 * https://blogs.msdn.microsoft.com/ndis/2015/03/21/mapping-from-ndis-oids-to-wmi-classes/
 * https://stackoverflow.com/questions/1431103/how-to-obtain-data-from-wmi-using-a-c-application
 * https://docs.microsoft.com/en-us/windows-hardware/drivers/network/oid-tcp-offload-parameters
 * https://wutils.com/wmi/root/wmi/ms_409/msndis_tcpoffloadcurrentconfig/
 * https://docs.microsoft.com/en-us/windows-hardware/drivers/network/oid-tcp-offload-current-config
 * https://wutils.com/wmi/root/wmi/msndis_tcpoffloadparameters/
 */

#ifdef OS_WIN32
#define WINVER _WIN32_WINNT_VISTA
#define _WIN32_WINNT _WIN32_WINNT_VISTA
#define NTDDI_VERSION NTDDI_VISTA

#include <inttypes.h>
#include <stdbool.h>

// clang-format off
#include <winsock2.h>
#include <windows.h>
#include <wbemidl.h>
#include <strsafe.h>
#include <ntddndis.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
// clang-format on

#include "util-debug.h"
#include "util-device.h"
#include "util-unittest.h"

#include "win32-syscall.h"

/**
 * \brief return only the GUID portion of the name
 */
static const char *StripPcapPrefix(const char *pcap_dev)
{
    return strchr(pcap_dev, '{');
}

/**
 * \brief: get the adapter address list, which includes IP status/details
 *
 * Clients MUST FREE the returned list to avoid memory leaks.
 */
static DWORD _GetAdaptersAddresses(IP_ADAPTER_ADDRESSES **pif_info_list)
{
    DWORD err = NO_ERROR;
    IP_ADAPTER_ADDRESSES *if_info_list;

    ULONG size = 0;
    err = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, NULL, &size);
    if (err != ERROR_BUFFER_OVERFLOW) {
        return err;
    }
    if_info_list = malloc((size_t)size);
    if (if_info_list == NULL) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    err = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, if_info_list, &size);
    if (err != NO_ERROR) {
        free(if_info_list);
        return err;
    }

    *pif_info_list = if_info_list;
    return NO_ERROR;
}

static DWORD FindAdapterAddresses(IP_ADAPTER_ADDRESSES *if_info_list,
                                  const char *adapter_name,
                                  IP_ADAPTER_ADDRESSES **pif_info)
{
    DWORD ret = NO_ERROR;
    adapter_name = StripPcapPrefix(adapter_name);
    *pif_info = NULL;

    for (IP_ADAPTER_ADDRESSES *current = if_info_list; current != NULL;
         current = current->Next) {

        /* if we find the adapter, return that data */
        if (strncmp(adapter_name, current->AdapterName, strlen(adapter_name)) ==
            0) {

            *pif_info = current;
            break;
        }
    }

    if (*pif_info == NULL) {
        ret = ERROR_NOT_FOUND;
    }

    return ret;
}

/**
 * \brief: get the maximum transmissible unit for the specified pcap device name
 */
int GetIfaceMTUWin32(const char *pcap_dev)
{
    HRESULT hr = S_OK;

    int mtu = 0;

    IP_ADAPTER_ADDRESSES *if_info_list = NULL, *if_info = NULL;
    hr = _GetAdaptersAddresses(&if_info_list);
    if (hr != S_OK) {
        mtu = -1;
        goto release;
    }
    hr = FindAdapterAddresses(if_info_list, pcap_dev, &if_info);
    if (hr != S_OK) {
        mtu = -1;
        goto release;
    }

    mtu = if_info->Mtu;

release:
    free(if_info_list);

    if (hr != S_OK) {
        const char *errbuf = NULL;
        FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                               FORMAT_MESSAGE_FROM_SYSTEM |
                               FORMAT_MESSAGE_IGNORE_INSERTS,
                       NULL, hr, 0, (LPTSTR)&errbuf, 0, NULL);

        SCLogWarning(SC_ERR_SYSCALL,
                     "Failure when trying to get MTU via syscall for '%s': %s "
                     "(%" PRId32 ")",
                     pcap_dev, errbuf, (uint32_t)hr);
    } else {
        SCLogInfo("Found an MTU of %d for '%s'", mtu, pcap_dev);
    }

    return mtu;
}

/**
 * \brief: get the maximum transmissible unit for all devices on the system
 */
int GetGlobalMTUWin32()
{
    uint32_t mtu = 0;

    DWORD err = NO_ERROR;
    IP_ADAPTER_ADDRESSES *if_info_list = NULL;

    /* get a list of all adapters' data */
    err = _GetAdaptersAddresses(&if_info_list);
    if (err != NO_ERROR) {
        goto fail;
    }

    /* now search for the right adapter in the list */
    IP_ADAPTER_ADDRESSES *if_info = NULL;
    for (if_info = if_info_list; if_info != NULL; if_info = if_info->Next) {
        /* -1 (uint) is an invalid value */
        if (if_info->Mtu != (uint32_t)-1) {
            continue;
        }

        /* we want to return the largest MTU value so we allocate enough */
        if (if_info->Mtu > mtu) {
            mtu = if_info->Mtu;
        }
    }

    free(if_info_list);

    SCLogInfo("Found a global MTU of %" PRIu32, mtu);
    return (int)mtu;

fail:
    free(if_info_list);

    const char *errbuf = NULL;
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                           FORMAT_MESSAGE_IGNORE_INSERTS,
                   NULL, err, 0, (LPTSTR)&errbuf, 0, NULL);

    SCLogWarning(
            SC_ERR_SYSCALL,
            "Failure when trying to get global MTU via syscall: %s (%" PRId32
            ")",
            errbuf, (uint32_t)err);

    return -1;
}

#define MAKE_VARIANT(v, type, value)                                           \
    VARIANT v;                                                                 \
    do {                                                                       \
        VariantInit(&v);                                                       \
        V_VT(&v) = VT_##type;                                                  \
        V_##type(&v) = (value);                                                \
    } while (0);

#define RELEASE_OBJECT(objptr)                                                 \
    do {                                                                       \
        if ((objptr) != NULL) {                                                \
            (objptr)->lpVtbl->Release(objptr);                                 \
        }                                                                      \
    } while (0);

typedef enum Win32TcpOffloadFlags_ {
    WIN32_TCP_OFFLOAD_FLAG_NONE = 0,
    WIN32_TCP_OFFLOAD_FLAG_CSUM_IP4RX = 1,
    WIN32_TCP_OFFLOAD_FLAG_CSUM_IP4TX = 1 << 1,
    WIN32_TCP_OFFLOAD_FLAG_CSUM_IP6RX = 1 << 2,
    WIN32_TCP_OFFLOAD_FLAG_CSUM_IP6TX = 1 << 3,
    WIN32_TCP_OFFLOAD_FLAG_LSOV1_IP4 = 1 << 4,
    WIN32_TCP_OFFLOAD_FLAG_LSOV2_IP4 = 1 << 5,
    WIN32_TCP_OFFLOAD_FLAG_LSOV2_IP6 = 1 << 6,

    /* aggregates */
    WIN32_TCP_OFFLOAD_FLAG_CSUM = WIN32_TCP_OFFLOAD_FLAG_CSUM_IP4RX |
                                  WIN32_TCP_OFFLOAD_FLAG_CSUM_IP4TX |
                                  WIN32_TCP_OFFLOAD_FLAG_CSUM_IP6RX |
                                  WIN32_TCP_OFFLOAD_FLAG_CSUM_IP6TX,
    WIN32_TCP_OFFLOAD_LSO = WIN32_TCP_OFFLOAD_FLAG_LSOV1_IP4 |
                            WIN32_TCP_OFFLOAD_FLAG_LSOV2_IP4 |
                            WIN32_TCP_OFFLOAD_FLAG_LSOV2_IP6,
} Win32TcpOffloadFlags;

typedef struct ComInstance_ {
    IWbemLocator *locator;
    IWbemServices *services;
} ComInstance;

/**
 * \brief Releases resources for a COM instance.
 */
static void ComInstanceRelease(ComInstance *instance)
{
    RELEASE_OBJECT(instance->services);
    RELEASE_OBJECT(instance->locator);
}

/**
 * \brief Creates a COM instance connected to the specified resource
 */
static HRESULT ComInstanceInit(ComInstance *instance, BSTR resource)
{
    HRESULT hr = S_OK;

    instance->locator = NULL;
    instance->services = NULL;

    /* connect to COM */
    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (hr != S_OK) {
        SCLogWarning(SC_ERR_SYSCALL, "COM CoInitializeEx failed: 0x%" PRIx32,
                     (uint32_t)hr);
        goto fail;
    }
    hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT,
                              RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE,
                              NULL);
    if (hr != S_OK) {
        SCLogWarning(SC_ERR_SYSCALL,
                     "COM CoInitializeSecurity failed: 0x%" PRIx32,
                     (uint32_t)hr);
        goto fail;
    }

    /* connect to WMI */
    hr = CoCreateInstance(&CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER,
                          &IID_IWbemLocator, (LPVOID *)&instance->locator);
    if (hr != S_OK) {
        SCLogWarning(SC_ERR_SYSCALL, "COM CoCreateInstance failed: 0x%" PRIx32,
                     (uint32_t)hr);
        goto fail;
    }
    hr = instance->locator->lpVtbl->ConnectServer(instance->locator, resource,
                                                  NULL, NULL, NULL, 0, NULL,
                                                  NULL, &instance->services);
    if (hr != S_OK) {
        SCLogWarning(SC_ERR_SYSCALL, "COM ConnectServer failed: 0x%" PRIx32,
                     (uint32_t)hr);
        goto fail;
    }

    return S_OK;

fail:
    ComInstanceRelease(instance);

    return hr;
}

typedef struct WmiMethod_ {
    ComInstance com_instance;

    BSTR object_name, method_name;

    IWbemClassObject *object;
    IWbemClassObject *in_params, *out_params;
} WmiMethod;

/**
 * \brief Releases resources for a WMI method handle
 */
static void WmiMethodRelease(WmiMethod *method)
{
    RELEASE_OBJECT(method->object);
    RELEASE_OBJECT(method->in_params);
    RELEASE_OBJECT(method->out_params);

    SysFreeString(method->method_name);
    SysFreeString(method->object_name);
    ComInstanceRelease(&method->com_instance);
}

/**
 * \brief initializes resources for a WMI method handle
 */
static HRESULT WmiMethodInit(WmiMethod *method, LPCWSTR object_name,
                             LPCWSTR method_name)
{
    HRESULT hr = S_OK;

    /* stick to WMI namespace */
    BSTR resource = SysAllocString(L"ROOT\\WMI");
    if (resource == NULL) {
        SCLogWarning(SC_ERR_SYSCALL, "Failed to allocate BSTR");
        goto fail;
    }
    method->object_name = SysAllocString(object_name);
    if (method->object_name == NULL) {
        SCLogWarning(SC_ERR_SYSCALL, "Failed to allocate BSTR");
        goto fail;
    }
    method->method_name = SysAllocString(method_name);
    if (method->method_name == NULL) {
        SCLogWarning(SC_ERR_SYSCALL, "Failed to allocate BSTR");
        goto fail;
    }

    /* initialize our COM instance */
    hr = ComInstanceInit(&method->com_instance, resource);
    SysFreeString(resource); /* no longer needed */
    if (hr != S_OK) {
        goto fail;
    }

    /* find our object to retrieve parameters */
    hr = method->com_instance.services->lpVtbl->GetObject(
            method->com_instance.services, method->object_name,
            WBEM_FLAG_RETURN_WBEM_COMPLETE, NULL, &method->object, NULL);
    if (hr != WBEM_S_NO_ERROR) {
        SCLogWarning(SC_ERR_SYSCALL, "WMI GetObject failed: 0x%" PRIx32,
                     (uint32_t)hr);
        goto fail;
    }

    /* find the method on the retrieved object */
    hr = method->object->lpVtbl->GetMethod(method->object, method_name, 0,
                                           &method->in_params,
                                           &method->out_params);
    if (hr != WBEM_S_NO_ERROR) {
        SCLogWarning(SC_ERR_SYSCALL, "WMI GetMethod failed: 0x%" PRIx32,
                     (uint32_t)hr);
        goto fail;
    }

    return S_OK;

fail:
    WmiMethodRelease(method);

    return hr;
}

typedef struct WmiMethodCall_ {
    WmiMethod *method;

    IWbemClassObject *in_params, *out_params;

    bool executed;
} WmiMethodCall;

/**
 *  \brief releases the WMI method call resources
 */
static void WmiMethodCallRelease(WmiMethodCall *call)
{
    RELEASE_OBJECT(call->in_params);
    RELEASE_OBJECT(call->out_params);
}

/**
 * \brief generates a single-use WMI method call
 */
static HRESULT WmiMethodCallInit(WmiMethodCall *call, WmiMethod *method)
{
    HRESULT hr = S_OK;

    call->in_params = NULL;
    call->out_params = NULL;
    call->executed = false;

    /* make an instance of the in/out params */
    hr = method->in_params->lpVtbl->SpawnInstance(method->in_params, 0,
                                                  &call->in_params);
    if (hr != S_OK) {
        SCLogWarning(SC_ERR_SYSCALL,
                     "WMI SpawnInstance failed on in_params: 0x%" PRIx32,
                     (uint32_t)hr);
        goto fail;
    }
    hr = method->out_params->lpVtbl->SpawnInstance(method->out_params, 0,
                                                   &call->out_params);
    if (hr != S_OK) {
        SCLogWarning(SC_ERR_SYSCALL,
                     "WMI SpawnInstance failed on out_params: 0x%" PRIx32,
                     (uint32_t)hr);
        goto fail;
    }

    return S_OK;

fail:
    WmiMethodCallRelease(call);

    return hr;
}

/**
 * \brief executes the method after the client has set applicable parameters.
 */
static HRESULT WmiMethodCallExec(WmiMethodCall *call)
{
    HRESULT hr = S_OK;

    if (call->executed) {
        return E_FAIL;
    }
    call->executed = true;

    hr = call->method->com_instance.services->lpVtbl->ExecMethod(
            call->method->com_instance.services, call->method->object_name,
            call->method->method_name, 0, NULL, call->in_params,
            &call->out_params, NULL);
    if (hr != WBEM_S_NO_ERROR) {
        SCLogWarning(SC_ERR_SYSCALL, "WMI ExecMethod failed: 0x%" PRIx32,
                     (uint32_t)hr);
        return hr;
    }

    return hr;
}

/**
 * Obtains an IWbemClassObject named property of a parent IWbemClassObject
 */
static HRESULT WbemGetSubObject(IWbemClassObject *object, LPCWSTR property_name,
                                IWbemClassObject **sub_object)
{
    HRESULT hr = S_OK;

    MAKE_VARIANT(out_var, UNKNOWN, NULL);

    hr = object->lpVtbl->Get(object, property_name, 0, &out_var, NULL, NULL);
    if (hr != WBEM_S_NO_ERROR) {
        goto release;
    }
    IUnknown *unknown = (IUnknown *)V_UNKNOWN(&out_var);
    hr = unknown->lpVtbl->QueryInterface(unknown, &IID_IWbemClassObject,
                                         (void **)sub_object);
    if (hr != S_OK) {
        SCLogWarning(SC_ERR_SYSCALL,
                     "WMI QueryInterface (IWbemClassObject) failed: 0x%" PRIx32,
                     (uint32_t)hr);
        goto release;
    }

release:
    VariantClear(&out_var);
    return hr;
}

/**
 * Obtains an Encapsulation value from an MSNdis_WmiOffload property
 */
static HRESULT GetEncapsulation(IWbemClassObject *object, LPCWSTR category,
                                LPCWSTR subcategory, ULONG *encapsulation)
{
    HRESULT hr = WBEM_S_NO_ERROR;

    IWbemClassObject *category_object = NULL;
    IWbemClassObject *subcategory_object = NULL;
    MAKE_VARIANT(out_var, UI4, 0);

    /* get category object */
    hr = WbemGetSubObject(object, category, &category_object);
    if (hr != WBEM_S_NO_ERROR) {
        goto release;
    }

    /* get sub-category object */
    hr = WbemGetSubObject(category_object, subcategory, &subcategory_object);
    if (hr != WBEM_S_NO_ERROR) {
        goto release;
    }
    hr = subcategory_object->lpVtbl->Get(subcategory_object, L"Encapsulation",
                                         0, &out_var, NULL, NULL);
    if (hr != WBEM_S_NO_ERROR) {
        goto release;
    }
    *encapsulation = V_UI4(&out_var);

release:
    VariantClear(&out_var);
    RELEASE_OBJECT(subcategory_object);
    RELEASE_OBJECT(category_object);
    return hr;
}

/**
 * \brief polls the NDIS TCP offloading status, namely LSOv1/v2
 */
static HRESULT GetNdisOffload(LPCWSTR friendly_name, uint64_t *offload_flags)
{
    if (friendly_name == NULL) {
        SCLogWarning(SC_ERR_SYSCALL, "No friendly name specified for device");
        return E_INVALIDARG;
    }

    HRESULT hr = S_OK;

    /* object instance path */
    LPCWSTR object_name_fmt = L"MSNdis_TcpOffloadCurrentConfig=\"%s\"";
    size_t n_chars = wcslen(object_name_fmt) + wcslen(friendly_name);
    LPWSTR object_name = malloc((n_chars + 1) * sizeof(wchar_t));
    object_name[n_chars] = 0; /* defensively null-terminate */
    hr = StringCchPrintfW(object_name, n_chars, object_name_fmt, friendly_name);
    /* method name */
    LPCWSTR method_name = L"WmiQueryCurrentOffloadConfig";

    /* connect to COM/WMI and obtain method */
    WmiMethod method = {};
    hr = WmiMethodInit(&method, object_name, method_name);
    if (hr != S_OK) {
        goto release;
    }

    /* make parameter instances */
    WmiMethodCall call = {};
    hr = WmiMethodCallInit(&call, &method);
    if (hr != S_OK) {
        goto release;
    }

    /* build parameters */
    /* MSNdis_ObjectHeader */
    BSTR ndis_object_header_name = SysAllocString(L"MSNdis_ObjectHeader");
    if (ndis_object_header_name == NULL) {
        SCLogWarning(SC_ERR_SYSCALL, "Failed to allocate BSTR");
        goto release;
    }
    IWbemClassObject *ndis_object_header;
    hr = method.com_instance.services->lpVtbl->GetObject(
            method.com_instance.services, ndis_object_header_name,
            WBEM_FLAG_RETURN_WBEM_COMPLETE, NULL, &ndis_object_header, NULL);
    if (hr != WBEM_S_NO_ERROR) {
        SCLogWarning(SC_ERR_SYSCALL, "WMI GetObject failed: 0x%" PRIx32,
                     (uint32_t)hr);
        goto release;
    }
    IUnknown *ndis_object_header_unknown = NULL;
    hr = ndis_object_header->lpVtbl->QueryInterface(
            ndis_object_header, &IID_IUnknown,
            (void **)&ndis_object_header_unknown);
    if (hr != S_OK) {
        SCLogWarning(SC_ERR_SYSCALL,
                     "WMI QueryInterface (IUnknown) failed: 0x%" PRIx32,
                     (uint32_t)hr);
        goto release;
    }

    /* Set parameters of MSNdis_ObjectHeader */
    MAKE_VARIANT(header_type, UI1, NDIS_WMI_OBJECT_TYPE_METHOD);
    hr = ndis_object_header->lpVtbl->Put(ndis_object_header, L"Type", 0,
                                         &header_type, VT_UI1);
    if (hr != WBEM_S_NO_ERROR) {
        goto release;
    }
    MAKE_VARIANT(header_revision, UI1, NDIS_WMI_METHOD_HEADER_REVISION_1);
    hr = ndis_object_header->lpVtbl->Put(ndis_object_header, L"Revision", 0,
                                         &header_revision, VT_UI1);
    if (hr != WBEM_S_NO_ERROR) {
        goto release;
    }
    MAKE_VARIANT(header_size, UI2, sizeof(NDIS_WMI_METHOD_HEADER));
    hr = ndis_object_header->lpVtbl->Put(ndis_object_header, L"Size", 0,
                                         &header_size, VT_UI2);
    if (hr != WBEM_S_NO_ERROR) {
        goto release;
    }

    /* Set values in MSNdis_WmiMethodHeader (in_params) */
    MAKE_VARIANT(ndis_object_header_var, UNKNOWN, ndis_object_header_unknown);
    hr = call.in_params->lpVtbl->Put(call.in_params, L"Header", 0,
                                     &ndis_object_header_var, VT_UNKNOWN);
    if (hr != WBEM_S_NO_ERROR) {
        goto release;
    }
    MAKE_VARIANT(net_luid, UI8, 0);
    hr = call.in_params->lpVtbl->Put(call.in_params, L"NetLuid", 0, &net_luid,
                                     VT_UI8);
    if (hr != WBEM_S_NO_ERROR) {
        goto release;
    }
    MAKE_VARIANT(port_number, UI4, 0);
    hr = call.in_params->lpVtbl->Put(call.in_params, L"PortNumber", 0,
                                     &port_number, VT_UI4);
    if (hr != WBEM_S_NO_ERROR) {
        goto release;
    }
    MAKE_VARIANT(request_id, UI8, 0);
    hr = call.in_params->lpVtbl->Put(call.in_params, L"RequestId", 0,
                                     &request_id, VT_UI8);
    if (hr != WBEM_S_NO_ERROR) {
        goto release;
    }
    MAKE_VARIANT(timeout, UI4, 5);
    hr = call.in_params->lpVtbl->Put(call.in_params, L"Timeout", 0, &timeout,
                                     VT_UI4);
    if (hr != WBEM_S_NO_ERROR) {
        goto release;
    }

    /* execute the method */
    hr = WmiMethodCallExec(&call);
    if (hr != S_OK) {
        goto release;
    }

    /* inspect the result */
    ULONG encapsulation;

    /* Checksum */
    hr = GetEncapsulation(call.out_params, L"Checksum", L"IPv4Receive",
                          &encapsulation);
    if (hr != WBEM_S_NO_ERROR) {
        goto release;
    }
    if (encapsulation != 0) {
        *offload_flags |= WIN32_TCP_OFFLOAD_FLAG_CSUM_IP4RX;
    }
    hr = GetEncapsulation(call.out_params, L"Checksum", L"IPv4Transmit",
                          &encapsulation);
    if (hr != WBEM_S_NO_ERROR) {
        goto release;
    }
    if (encapsulation != 0) {
        *offload_flags |= WIN32_TCP_OFFLOAD_FLAG_CSUM_IP4TX;
    }
    hr = GetEncapsulation(call.out_params, L"Checksum", L"IPv6Receive",
                          &encapsulation);
    if (hr != WBEM_S_NO_ERROR) {
        goto release;
    }
    if (encapsulation != 0) {
        *offload_flags |= WIN32_TCP_OFFLOAD_FLAG_CSUM_IP6RX;
    }
    hr = GetEncapsulation(call.out_params, L"Checksum", L"IPv6Transmit",
                          &encapsulation);
    if (hr != WBEM_S_NO_ERROR) {
        goto release;
    }
    if (encapsulation != 0) {
        *offload_flags |= WIN32_TCP_OFFLOAD_FLAG_CSUM_IP6TX;
    }

    /* LsoV1 */
    hr = GetEncapsulation(call.out_params, L"LsoV1", L"WmiIPv4",
                          &encapsulation);
    if (hr != WBEM_S_NO_ERROR) {
        goto release;
    }
    if (encapsulation != 0) {
        *offload_flags |= WIN32_TCP_OFFLOAD_FLAG_LSOV1_IP4;
    }

    /* LsoV2 */
    hr = GetEncapsulation(call.out_params, L"LsoV2", L"WmiIPv4",
                          &encapsulation);
    if (hr != WBEM_S_NO_ERROR) {
        goto release;
    }
    if (encapsulation != 0) {
        *offload_flags |= WIN32_TCP_OFFLOAD_FLAG_LSOV2_IP4;
    }
    hr = GetEncapsulation(call.out_params, L"LsoV2", L"WmiIPv6",
                          &encapsulation);
    if (hr != WBEM_S_NO_ERROR) {
        goto release;
    }
    if (encapsulation != 0) {
        *offload_flags |= WIN32_TCP_OFFLOAD_FLAG_LSOV2_IP6;
    }

release:
    VariantClear(&timeout);
    VariantClear(&request_id);
    VariantClear(&port_number);
    VariantClear(&net_luid);
    VariantClear(&header_size);
    VariantClear(&header_revision);
    VariantClear(&header_type);
    VariantClear(&ndis_object_header_var);

    RELEASE_OBJECT(ndis_object_header);
    SysFreeString(ndis_object_header_name);

    WmiMethodCallRelease(&call);
    WmiMethodRelease(&method);

    return hr;
}

int GetIfaceOffloadingWin32(const char *pcap_dev, int csum, int other)
{
    int ret = 0;
    uint64_t offload_flags = 0;

    /* WMI uses the friendly name as an identifier... */
    IP_ADAPTER_ADDRESSES *if_info_list = NULL, *if_info = NULL;
    DWORD err = _GetAdaptersAddresses(&if_info_list);
    if (err != NO_ERROR) {
        SCLogWarning(SC_ERR_SYSCALL,
                     "Failure when trying to get feature via syscall for '%s': "
                     "%s (0x%" PRIx32 ")",
                     pcap_dev, strerror((int)err), (uint32_t)err);
        ret = -1;
        goto release;
    }
    err = FindAdapterAddresses(if_info_list, pcap_dev, &if_info);
    if (err != NO_ERROR) {
        SCLogWarning(SC_ERR_SYSCALL,
                     "Failure when trying to get feature via syscall for '%s': "
                     "%s (0x%" PRIx32 ")",
                     pcap_dev, strerror((int)err), (uint32_t)err);
        ret = -1;
        goto release;
    }
    LPWSTR if_friendly_name = if_info->FriendlyName;

    HRESULT hr = GetNdisOffload(if_friendly_name, &offload_flags);
    if (hr != S_OK) {
        SCLogWarning(SC_ERR_SYSCALL,
                     "Failure when trying to get feature via syscall for '%s': "
                     "%s (0x%" PRIx32 ")",
                     pcap_dev, strerror((int)hr), (uint32_t)hr);
        ret = -1;
        goto release;
    } else if (offload_flags != 0) {
        if (csum == 1) {
            if ((offload_flags & WIN32_TCP_OFFLOAD_FLAG_CSUM) != 0) {
                ret = 1;
            }
        }
        if (other == 1) {
            if ((offload_flags & WIN32_TCP_OFFLOAD_LSO) != 0) {
                ret = 1;
            }
        }
    }

    if (ret == 0) {
        SCLogPerf("NIC offloading on %s: Checksum IPv4 Rx: %d Tx: %d IPv6 "
                  "Rx: %d Tx: %d LSOv1 IPv4: %d LSOv2 IPv4: %d IPv6: %d",
                  pcap_dev,
                  (offload_flags & WIN32_TCP_OFFLOAD_FLAG_CSUM_IP4RX) != 0,
                  (offload_flags & WIN32_TCP_OFFLOAD_FLAG_CSUM_IP4TX) != 0,
                  (offload_flags & WIN32_TCP_OFFLOAD_FLAG_CSUM_IP6RX) != 0,
                  (offload_flags & WIN32_TCP_OFFLOAD_FLAG_CSUM_IP6TX) != 0,
                  (offload_flags & WIN32_TCP_OFFLOAD_FLAG_LSOV1_IP4) != 0,
                  (offload_flags & WIN32_TCP_OFFLOAD_FLAG_LSOV2_IP4) != 0,
                  (offload_flags & WIN32_TCP_OFFLOAD_FLAG_LSOV2_IP6) != 0);
    } else {
        SCLogWarning(SC_ERR_NIC_OFFLOADING,
                     "NIC offloading on %s: Checksum IPv4 Rx: %d Tx: %d IPv6 "
                     "Rx: %d Tx: %d LSOv1 IPv4: %d LSOv2 IPv4: %d IPv6: %d",
                     pcap_dev,
                     (offload_flags & WIN32_TCP_OFFLOAD_FLAG_CSUM_IP4RX) != 0,
                     (offload_flags & WIN32_TCP_OFFLOAD_FLAG_CSUM_IP4TX) != 0,
                     (offload_flags & WIN32_TCP_OFFLOAD_FLAG_CSUM_IP6RX) != 0,
                     (offload_flags & WIN32_TCP_OFFLOAD_FLAG_CSUM_IP6TX) != 0,
                     (offload_flags & WIN32_TCP_OFFLOAD_FLAG_LSOV1_IP4) != 0,
                     (offload_flags & WIN32_TCP_OFFLOAD_FLAG_LSOV2_IP4) != 0,
                     (offload_flags & WIN32_TCP_OFFLOAD_FLAG_LSOV2_IP6) != 0);
    }

release:
    free(if_info_list);

    return ret;
}

int DisableIfaceOffloadingWin32(LiveDevice *ldev) { return 0; }

int RestoreIfaceOffloadingWin32(LiveDevice *ldev) { return 0; }

#ifdef UNITTESTS
static int Win32TestStripPcapPrefix(void)
{
    int result = 1;

    const char *name1 = "\\Device\\NPF_{D4A32435-1BA7-4008-93A6-1518AA4BBD9B}";
    const char *expect_name1 = "{D4A32435-1BA7-4008-93A6-1518AA4BBD9B}";

    const char *name2 = "{D4A32435-1BA7-4008-93A6-1518AA4BBD9B}";
    const char *expect_name2 = "{D4A32435-1BA7-4008-93A6-1518AA4BBD9B}";

    result &= (strncmp(expect_name1, StripPcapPrefix(name1),
                       strlen(expect_name1)) == 0);

    result &= (strncmp(expect_name2, StripPcapPrefix(name2),
                       strlen(expect_name2)) == 0);

    return result;
}
#endif /* UNITTESTS */

void Win32SyscallRegisterTests()
{
#ifdef UNITTESTS
    UtRegisterTest("Win32TestStripPcapPrefix", Win32TestStripPcapPrefix);
#endif
}

#endif /* OS_WIN32 */
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
 * https://msdn.microsoft.com/en-us/library/aa390421(v=vs.85).aspx
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

static HMODULE wmiutils_dll = NULL;

/**
 * \brief obtain the WMI utilities DLL
 */
static HMODULE WmiUtils(void)
{
    if (wmiutils_dll == NULL) {
        wmiutils_dll =
                LoadLibraryA("C:\\Windows\\System32\\wbem\\wmiutils.dll");
    }

    return wmiutils_dll;
}

/**
 * \brief allocate a BSTR from a converted integer
 */
static BSTR itob(int i)
{
    wchar_t buf[11];
    _itow(i, buf, 10);
    return SysAllocString(buf);
}

/**
 * \brief allocate a BSTR from a converted unsigned integer
 */
static BSTR utob(uint64_t ui)
{
    wchar_t buf[20];
    _itow(ui, buf, 10);
    return SysAllocString(buf);
}

/**
 * \brief Get the win32/wmi error string
 */
static const char *GetErrorString(DWORD error_code)
{
    char *error_string = NULL;
    FormatMessageA(
            FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_ALLOCATE_BUFFER |
                    FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            WmiUtils(), error_code, 0, (LPTSTR)&error_string, 0, NULL);

    error_string[strlen(error_string) - 2] = 0; // remove line breaks

    return error_string;
}

/**
 * \brief log an HRESULT in-place
 */
#define Win32LogDebug(hr)                                                      \
    do {                                                                       \
        const char *error_string = GetErrorString(hr);                         \
        SCLogDebug("HRESULT: %s (0x%" PRIx32 ")", error_string,                \
                   (uint32_t)(hr));                                            \
        LocalFree((LPVOID)error_string);                                       \
    } while (0);

/**
 * \brief return only the GUID portion of the name
 */
static const char *StripPcapPrefix(const char *pcap_dev)
{
    return strchr(pcap_dev, '{');
}

/**
 * \brief get the adapter address list, which includes IP status/details
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
 * \brief get the maximum transmissible unit for the specified pcap device name
 */
int GetIfaceMTUWin32(const char *pcap_dev)
{
    DWORD err = NO_ERROR;

    int mtu = 0;

    IP_ADAPTER_ADDRESSES *if_info_list = NULL, *if_info = NULL;
    err = _GetAdaptersAddresses(&if_info_list);
    if (err != NO_ERROR) {
        mtu = -1;
        goto fail;
    }
    err = FindAdapterAddresses(if_info_list, pcap_dev, &if_info);
    if (err != NO_ERROR) {
        mtu = -1;
        goto fail;
    }

    mtu = if_info->Mtu;

fail:
    free(if_info_list);

    if (err != S_OK) {
        const char *errbuf = GetErrorString(err);
        SCLogWarning(SC_ERR_SYSCALL,
                     "Failure when trying to get MTU via syscall for '%s': %s "
                     "(%" PRId32 ")",
                     pcap_dev, errbuf, (uint32_t)err);
        LocalFree((LPVOID)errbuf);
    } else {
        SCLogInfo("Found an MTU of %d for '%s'", mtu, pcap_dev);
    }

    return mtu;
}

/**
 * \brief get the maximum transmissible unit for all devices on the system
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

#define ReleaseObject(objptr)                                                  \
    do {                                                                       \
        if ((objptr) != NULL) {                                                \
            (objptr)->lpVtbl->Release(objptr);                                 \
            (objptr) = NULL;                                                   \
        }                                                                      \
    } while (0);

#ifdef DEBUG
#define DebugPrintWmiObject(object)                                            \
    do {                                                                       \
        if ((object) == NULL) {                                                \
            SCLogDebug("NULL");                                                \
            break;                                                             \
        }                                                                      \
        BSTR str = NULL;                                                       \
        (object)->lpVtbl->GetObjectText((object), 0, &str);                    \
        char *strA = malloc(SysStringLen(str));                                \
        wcstombs(strA, str, SysStringLen(str));                                \
        SCLogDebug("\n%s", strA);                                              \
        free(strA);                                                            \
        SysFreeString(str);                                                    \
    } while (0);
#else
#define DebugPrintWmiObject(object)
#endif

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
 * \brief Creates a COM instance connected to the specified resource
 */
static HRESULT ComInstanceInit(ComInstance *instance, LPCWSTR resource)
{
    HRESULT hr = S_OK;

    instance->locator = NULL;
    instance->services = NULL;

    BSTR resource_bstr = SysAllocString(resource);
    if (resource_bstr == NULL) {
        hr = HRESULT_FROM_WIN32(E_OUTOFMEMORY);
        SCLogWarning(SC_ERR_SYSCALL, "Failed to allocate BSTR");
        goto fail;
    }

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
    hr = instance->locator->lpVtbl->ConnectServer(
            instance->locator, resource_bstr, NULL, NULL, NULL, 0, NULL, NULL,
            &instance->services);
    if (hr != S_OK) {
        SCLogWarning(SC_ERR_SYSCALL, "COM ConnectServer failed: 0x%" PRIx32,
                     (uint32_t)hr);
        goto fail;
    }

fail:
    SysFreeString(resource_bstr);

    return hr;
}

/**
 * \brief Releases resources for a COM instance.
 */
static void ComInstanceRelease(ComInstance *instance)
{
    if (instance == NULL) {
        return;
    }
    ReleaseObject(instance->services);
    ReleaseObject(instance->locator);
}

/**
 * \brief obtains a class definition from COM services
 */
static HRESULT GetWbemClass(ComInstance *instance, LPCWSTR name,
                            IWbemClassObject **p_class)
{
    HRESULT hr = WBEM_S_NO_ERROR;
    BSTR name_bstr = NULL;

    if (instance == NULL || name == NULL || p_class == NULL ||
        *p_class != NULL) {
        hr = HRESULT_FROM_WIN32(E_INVALIDARG);
        Win32LogDebug(hr);
        goto fail;
    }

    /* allocate name string */
    name_bstr = SysAllocString(name);
    if (name_bstr == NULL) {
        hr = HRESULT_FROM_WIN32(E_OUTOFMEMORY);
        SCLogWarning(SC_ERR_SYSCALL, "Failed to allocate BSTR");
        goto fail;
    }

    /* obtain object */
    hr = instance->services->lpVtbl->GetObject(instance->services, name_bstr,
                                               WBEM_FLAG_RETURN_WBEM_COMPLETE,
                                               NULL, p_class, NULL);
    if (hr != S_OK) {
        SCLogWarning(SC_ERR_SYSCALL, "WMI GetObject failed: 0x%" PRIx32,
                     (uint32_t)hr);
        goto fail;
    }

fail:
    SysFreeString(name_bstr);

    return hr;
}

typedef struct WbemMethod_ {
    ComInstance *com_instance;

    BSTR method_name;

    IWbemClassObject *in_params, *out_params;
} WbemMethod;

/**
 * \brief initializes resources for a WMI method handle
 */
static HRESULT GetWbemMethod(ComInstance *com_instance, LPCWSTR class_name,
                             LPCWSTR method_name, WbemMethod *method)
{
    HRESULT hr = S_OK;
    IWbemClassObject *class = NULL;

    method->com_instance = com_instance;

    BSTR class_name_bstr = SysAllocString(class_name);
    if (class_name_bstr == NULL) {
        hr = HRESULT_FROM_WIN32(E_OUTOFMEMORY);
        SCLogWarning(SC_ERR_SYSCALL, "Failed to allocate BSTR");
        goto fail;
    }
    method->method_name = SysAllocString(method_name);
    if (method->method_name == NULL) {
        hr = HRESULT_FROM_WIN32(E_OUTOFMEMORY);
        SCLogWarning(SC_ERR_SYSCALL, "Failed to allocate BSTR");
        goto fail;
    }

    /* find our class definition to retrieve parameters */
    hr = GetWbemClass(com_instance, class_name, &class);
    if (hr != WBEM_S_NO_ERROR) {
        goto fail;
    }

    /* find the method on the retrieved class */
    hr = class->lpVtbl->GetMethod(class, method_name, 0, &method->in_params,
                                  &method->out_params);
    if (hr != WBEM_S_NO_ERROR) {
        SCLogWarning(SC_ERR_SYSCALL, "WMI GetMethod failed: 0x%" PRIx32,
                     (uint32_t)hr);
        goto fail;
    }

fail:
    ReleaseObject(class);

    SysFreeString(class_name_bstr);

    return hr;
}

/**
 * \brief Releases resources for a WMI method handle
 */
static void WbemMethodRelease(WbemMethod *method)
{
    if (method == NULL) {
        return;
    }
    ReleaseObject(method->in_params);
    ReleaseObject(method->out_params);

    SysFreeString(method->method_name);
}

typedef struct WbemMethodCall_ {
    WbemMethod *method;

    BSTR instance_path;

    IWbemClassObject *in_params, *out_params;
} WbemMethodCall;

/**
 * \brief generates a single-use WMI method call
 */
static HRESULT GetWbemMethodCall(WbemMethod *method, LPCWSTR instance_path,
                                 WbemMethodCall *call)
{
    HRESULT hr = S_OK;

    call->method = method;
    call->instance_path = SysAllocString(instance_path);
    if (call->instance_path == NULL) {
        hr = HRESULT_FROM_WIN32(E_OUTOFMEMORY);
        SCLogWarning(SC_ERR_SYSCALL, "Failed to allocate BSTR: 0x%" PRIx32,
                     (uint32_t)hr);
        goto fail;
    }

    /* make an instance of the in/out params */
    hr = method->in_params->lpVtbl->SpawnInstance(method->in_params, 0,
                                                  &call->in_params);
    if (hr != S_OK) {
        SCLogWarning(SC_ERR_SYSCALL,
                     "WMI SpawnInstance failed on in_params: 0x%" PRIx32,
                     (uint32_t)hr);
        goto fail;
    }

    method->out_params = NULL;

fail:
    return hr;
}

/**
 *  \brief releases the WMI method call resources
 */
static void WbemMethodCallRelease(WbemMethodCall *call)
{
    if (call == NULL) {
        return;
    }
    ReleaseObject(call->in_params);
    ReleaseObject(call->out_params);

    SysFreeString(call->instance_path);
}

/**
 * \brief executes the method after the client has set applicable parameters.
 */
static HRESULT WbemMethodCallExec(WbemMethodCall *call)
{
    HRESULT hr = S_OK;

    hr = call->method->com_instance->services->lpVtbl->ExecMethod(
            call->method->com_instance->services, call->instance_path,
            call->method->method_name, 0, NULL, call->in_params,
            &call->out_params, NULL);
    if (hr != WBEM_S_NO_ERROR) {
        SCLogWarning(SC_ERR_SYSCALL, "WMI ExecMethod failed: 0x%" PRIx32,
                     (uint32_t)hr);
        goto fail;
    }

fail:
    return hr;
}

/**
 * Obtains an IWbemClassObject named property of a parent IWbemClassObject
 */
static HRESULT WbemGetSubObject(IWbemClassObject *object, LPCWSTR property_name,
                                IWbemClassObject **sub_object)
{
    HRESULT hr = S_OK;

    VARIANT out_var;
    VariantInit(&out_var);
    hr = object->lpVtbl->Get(object, property_name, 0, &out_var, NULL, NULL);
    if (hr != WBEM_S_NO_ERROR) {
        goto fail;
    }

    IUnknown *unknown = V_UNKNOWN(&out_var);
    hr = unknown->lpVtbl->QueryInterface(unknown, &IID_IWbemClassObject,
                                         (void **)sub_object);
    if (hr != S_OK) {
        SCLogWarning(SC_ERR_SYSCALL,
                     "WMI QueryInterface (IWbemClassObject) failed: 0x%" PRIx32,
                     (uint32_t)hr);
        goto fail;
    }

fail:
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

    VARIANT out_var;
    VariantInit(&out_var);

    /* get category object */
    hr = WbemGetSubObject(object, category, &category_object);
    if (hr != WBEM_S_NO_ERROR) {
        goto fail;
    }

    /* get sub-category object */
    hr = WbemGetSubObject(category_object, subcategory, &subcategory_object);
    if (hr != WBEM_S_NO_ERROR) {
        goto fail;
    }
    hr = subcategory_object->lpVtbl->Get(subcategory_object, L"Encapsulation",
                                         0, &out_var, NULL, NULL);
    if (hr != WBEM_S_NO_ERROR) {
        goto fail;
    }
    *encapsulation = V_UI4(&out_var);

fail:
    VariantClear(&out_var);
    ReleaseObject(subcategory_object);
    ReleaseObject(category_object);
    return hr;
}

static HRESULT GetIUnknown(IWbemClassObject *object, IUnknown **p_unknown)
{
    HRESULT hr = WBEM_S_NO_ERROR;

    if (object == NULL || p_unknown == NULL || *p_unknown != NULL) {
        hr = HRESULT_FROM_WIN32(E_INVALIDARG);
        Win32LogDebug(hr);
        goto fail;
    }

    hr = object->lpVtbl->QueryInterface(object, &IID_IUnknown,
                                        (void **)p_unknown);
    if (hr != S_OK) {
        SCLogWarning(SC_ERR_SYSCALL,
                     "WMI QueryInterface (IUnknown) failed: 0x%" PRIx32,
                     (uint32_t)hr);
        goto fail;
    }

fail:
    return hr;
}

static HRESULT BuildNdisObjectHeader(ComInstance *instance, int type,
                                     int revision,
                                     IWbemClassObject **p_ndis_object_header)
{
    HRESULT hr = WBEM_S_NO_ERROR;

    if (instance == NULL || p_ndis_object_header == NULL ||
        *p_ndis_object_header != NULL) {

        hr = HRESULT_FROM_WIN32(E_INVALIDARG);
        Win32LogDebug(hr);
        goto fail;
    }

    /* obtain object */
    hr = GetWbemClass(instance, L"MSNdis_ObjectHeader", p_ndis_object_header);
    if (hr != WBEM_S_NO_ERROR) {
        goto fail;
    }

    VARIANT param_variant;
    VariantInit(&param_variant);
    IWbemClassObject *ndis_object_header = *p_ndis_object_header;

    /* set parameters */
    V_VT(&param_variant) = VT_UI1;
    V_UI1(&param_variant) = type;
    hr = ndis_object_header->lpVtbl->Put(ndis_object_header, L"Type", 0,
                                         &param_variant, 0);
    VariantClear(&param_variant);
    if (hr != WBEM_S_NO_ERROR) {
        Win32LogDebug(hr);
        goto fail;
    }

    V_VT(&param_variant) = VT_UI1;
    V_UI1(&param_variant) = revision;
    hr = ndis_object_header->lpVtbl->Put(ndis_object_header, L"Revision", 0,
                                         &param_variant, 0);
    VariantClear(&param_variant);
    if (hr != WBEM_S_NO_ERROR) {
        Win32LogDebug(hr);
        goto fail;
    }

    /* https://docs.microsoft.com/en-us/windows-hardware/drivers/network/ndis-object-version-issues-for-wmi
     */
    V_VT(&param_variant) = VT_I4;
    V_I4(&param_variant) = 0xFFFF;
    hr = ndis_object_header->lpVtbl->Put(ndis_object_header, L"Size", 0,
                                         &param_variant, 0);
    VariantClear(&param_variant);
    if (hr != WBEM_S_NO_ERROR) {
        Win32LogDebug(hr);
        goto fail;
    }

fail:
    return hr;
}

static HRESULT BuildNdisWmiMethodHeader(ComInstance *instance,
                                        uint64_t net_luid, uint32_t port_number,
                                        uint64_t request_id, uint32_t timeout,
                                        IWbemClassObject **p_ndis_method_header)
{
    HRESULT hr = WBEM_S_NO_ERROR;
    IWbemClassObject *ndis_object_header = NULL;
    IUnknown *ndis_object_header_unknown = NULL;

    if (instance == NULL || p_ndis_method_header == NULL ||
        *p_ndis_method_header != NULL) {

        hr = HRESULT_FROM_WIN32(E_INVALIDARG);
        Win32LogDebug(hr);
        goto fail;
    }

    /* obtain object */
    hr = GetWbemClass(instance, L"MSNdis_WmiMethodHeader",
                      p_ndis_method_header);
    if (hr != WBEM_S_NO_ERROR) {
        goto fail;
    }

    /* get embedded MSNdis_ObjectHeader */
    hr = BuildNdisObjectHeader(instance, NDIS_WMI_OBJECT_TYPE_METHOD,
                               NDIS_WMI_METHOD_HEADER_REVISION_1,
                               &ndis_object_header);
    if (hr != WBEM_S_NO_ERROR) {
        goto fail;
    }
    hr = GetIUnknown(ndis_object_header, &ndis_object_header_unknown);
    if (hr != WBEM_S_NO_ERROR) {
        goto fail;
    }

    VARIANT param_variant;
    VariantInit(&param_variant);
    IWbemClassObject *ndis_method_header = *p_ndis_method_header;

    /* set parameters */
    V_VT(&param_variant) = VT_UNKNOWN;
    V_UNKNOWN(&param_variant) = ndis_object_header_unknown;
    hr = ndis_method_header->lpVtbl->Put(ndis_method_header, L"Header", 0,
                                         &param_variant, 0);
    VariantClear(&param_variant);
    if (hr != WBEM_S_NO_ERROR) {
        Win32LogDebug(hr);
        goto fail;
    }

    V_VT(&param_variant) = VT_BSTR;
    V_BSTR(&param_variant) = utob(net_luid);
    hr = ndis_method_header->lpVtbl->Put(ndis_method_header, L"NetLuid", 0,
                                         &param_variant, 0);
    VariantClear(&param_variant);
    if (hr != WBEM_S_NO_ERROR) {
        Win32LogDebug(hr);
        goto fail;
    }

    V_VT(&param_variant) = VT_BSTR;
    V_BSTR(&param_variant) = utob((uint64_t)port_number);
    hr = ndis_method_header->lpVtbl->Put(ndis_method_header, L"PortNumber", 0,
                                         &param_variant, 0);
    VariantClear(&param_variant);
    if (hr != WBEM_S_NO_ERROR) {
        Win32LogDebug(hr);
        goto fail;
    }

    V_VT(&param_variant) = VT_BSTR;
    V_BSTR(&param_variant) = utob(request_id);
    hr = ndis_method_header->lpVtbl->Put(ndis_method_header, L"RequestId", 0,
                                         &param_variant, 0);
    VariantClear(&param_variant);
    if (hr != WBEM_S_NO_ERROR) {
        Win32LogDebug(hr);
        goto fail;
    }

    V_VT(&param_variant) = VT_BSTR;
    V_BSTR(&param_variant) = utob((uint64_t)timeout);
    hr = ndis_method_header->lpVtbl->Put(ndis_method_header, L"Timeout", 0,
                                         &param_variant, 0);
    VariantClear(&param_variant);
    if (hr != WBEM_S_NO_ERROR) {
        Win32LogDebug(hr);
        goto fail;
    }

    V_VT(&param_variant) = VT_BSTR;
    V_BSTR(&param_variant) = utob((uint64_t)0);
    hr = ndis_method_header->lpVtbl->Put(ndis_method_header, L"Padding", 0,
                                         &param_variant, 0);
    VariantClear(&param_variant);
    if (hr != WBEM_S_NO_ERROR) {
        Win32LogDebug(hr);
        goto fail;
    }

fail:
    ReleaseObject(ndis_object_header);

    return hr;
}

/**
 * \brief polls the NDIS TCP offloading status, namely LSOv1/v2
 */
static HRESULT GetNdisOffload(LPCWSTR if_description, uint64_t *offload_flags)
{
    if (if_description == NULL) {
        SCLogWarning(SC_ERR_SYSCALL, "No description specified for device");
        return E_INVALIDARG;
    }

    HRESULT hr = S_OK;

    ComInstance instance = {};
    WbemMethod method = {};
    WbemMethodCall call = {};

    IWbemClassObject *ndis_method_header = NULL;
    IUnknown *ndis_method_header_unknown = NULL;
    IWbemClassObject *ndis_offload = NULL;

    LPCWSTR class_name = L"MSNdis_TcpOffloadCurrentConfig";
    LPCWSTR instance_name_fmt = L"%s=\"%s\"";
    size_t n_chars = wcslen(class_name) + wcslen(if_description) +
                     wcslen(instance_name_fmt);
    LPWSTR instance_name = malloc((n_chars + 1) * sizeof(wchar_t));
    instance_name[n_chars] = 0; /* defensively null-terminate */
    hr = StringCchPrintfW(instance_name, n_chars, instance_name_fmt, class_name,
                          if_description);
    /* method name */
    LPCWSTR method_name = L"WmiQueryCurrentOffloadConfig";

    /* connect to COM/WMI */
    hr = ComInstanceInit(&instance, L"ROOT\\WMI");
    if (hr != S_OK) {
        goto fail;
    }

    /* obtain method */
    hr = GetWbemMethod(&instance, class_name, method_name, &method);
    if (hr != S_OK) {
        goto fail;
    }

    /* make parameter instances */
    hr = GetWbemMethodCall(&method, instance_name, &call);
    if (hr != S_OK) {
        goto fail;
    }

    /* build parameters */

    /* Make MSNdis_WmiMethodHeader */
    hr = BuildNdisWmiMethodHeader(&instance, 0, 0, 0, 5, &ndis_method_header);
    if (hr != WBEM_S_NO_ERROR) {
        goto fail;
    }
    hr = GetIUnknown(ndis_method_header, &ndis_method_header_unknown);
    if (hr != WBEM_S_NO_ERROR) {
        goto fail;
    }

    VARIANT param_variant;
    VariantInit(&param_variant);

    /* Set in_params */
    V_VT(&param_variant) = VT_UNKNOWN;
    V_UNKNOWN(&param_variant) = ndis_method_header_unknown;
    hr = call.in_params->lpVtbl->Put(call.in_params, L"Header", 0,
                                     &param_variant, 0);
    VariantClear(&param_variant);
    if (hr != WBEM_S_NO_ERROR) {
        Win32LogDebug(hr);
        goto fail;
    }

    DebugPrintWmiObject(call.in_params);
    DebugPrintWmiObject(call.out_params);

    /* execute the method */
    hr = WbemMethodCallExec(&call);
    if (hr != S_OK) {
        goto fail;
    }

    /* inspect the result */
    hr = WbemGetSubObject(call.out_params, L"Offload", &ndis_offload);
    if (hr != WBEM_S_NO_ERROR) {
        goto fail;
    }
    ULONG encapsulation = 0;

    /* Checksum */
    hr = GetEncapsulation(ndis_offload, L"Checksum", L"IPv4Receive",
                          &encapsulation);
    if (hr != WBEM_S_NO_ERROR) {
        Win32LogDebug(hr);
        goto fail;
    }
    if (encapsulation != 0) {
        *offload_flags |= WIN32_TCP_OFFLOAD_FLAG_CSUM_IP4RX;
    }
    hr = GetEncapsulation(ndis_offload, L"Checksum", L"IPv4Transmit",
                          &encapsulation);
    if (hr != WBEM_S_NO_ERROR) {
        Win32LogDebug(hr);
        goto fail;
    }
    if (encapsulation != 0) {
        *offload_flags |= WIN32_TCP_OFFLOAD_FLAG_CSUM_IP4TX;
    }
    hr = GetEncapsulation(ndis_offload, L"Checksum", L"IPv6Receive",
                          &encapsulation);
    if (hr != WBEM_S_NO_ERROR) {
        Win32LogDebug(hr);
        goto fail;
    }
    if (encapsulation != 0) {
        *offload_flags |= WIN32_TCP_OFFLOAD_FLAG_CSUM_IP6RX;
    }
    hr = GetEncapsulation(ndis_offload, L"Checksum", L"IPv6Transmit",
                          &encapsulation);
    if (hr != WBEM_S_NO_ERROR) {
        Win32LogDebug(hr);
        goto fail;
    }
    if (encapsulation != 0) {
        *offload_flags |= WIN32_TCP_OFFLOAD_FLAG_CSUM_IP6TX;
    }

    /* LsoV1 */
    hr = GetEncapsulation(ndis_offload, L"LsoV1", L"WmiIPv4", &encapsulation);
    if (hr != WBEM_S_NO_ERROR) {
        Win32LogDebug(hr);
        goto fail;
    }
    if (encapsulation != 0) {
        *offload_flags |= WIN32_TCP_OFFLOAD_FLAG_LSOV1_IP4;
    }

    /* LsoV2 */
    hr = GetEncapsulation(ndis_offload, L"LsoV2", L"WmiIPv4", &encapsulation);
    if (hr != WBEM_S_NO_ERROR) {
        Win32LogDebug(hr);
        goto fail;
    }
    if (encapsulation != 0) {
        *offload_flags |= WIN32_TCP_OFFLOAD_FLAG_LSOV2_IP4;
    }
    hr = GetEncapsulation(ndis_offload, L"LsoV2", L"WmiIPv6", &encapsulation);
    if (hr != WBEM_S_NO_ERROR) {
        Win32LogDebug(hr);
        goto fail;
    }
    if (encapsulation != 0) {
        *offload_flags |= WIN32_TCP_OFFLOAD_FLAG_LSOV2_IP6;
    }

fail:

    ReleaseObject(ndis_method_header);
    ReleaseObject(ndis_offload);

    WbemMethodCallRelease(&call);
    WbemMethodRelease(&method);
    ComInstanceRelease(&instance);

    return hr;
}

int GetIfaceOffloadingWin32(const char *pcap_dev, int csum, int other)
{
    DWORD err = NO_ERROR;
    int ret = 0;
    uint64_t offload_flags = 0;

    /* WMI uses the description as an identifier... */
    IP_ADAPTER_ADDRESSES *if_info_list = NULL, *if_info = NULL;
    err = _GetAdaptersAddresses(&if_info_list);
    if (err != NO_ERROR) {
        ret = -1;
        goto fail;
    }
    err = FindAdapterAddresses(if_info_list, pcap_dev, &if_info);
    if (err != NO_ERROR) {
        ret = -1;
        goto fail;
    }
    LPWSTR if_description = if_info->Description;

    /* now query WMI for the offload info */
    err = GetNdisOffload(if_description, &offload_flags);
    if (err != S_OK) {
        ret = -1;
        goto fail;
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

fail:
    if (ret == -1) {
        const char *errstr = GetErrorString(err);
        SCLogWarning(SC_ERR_SYSCALL,
                     "Failure when trying to get feature via syscall for '%s': "
                     "%s (0x%" PRIx32 ")",
                     pcap_dev, errstr, (uint32_t)err);
        LocalFree((LPVOID)errstr);
    }

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
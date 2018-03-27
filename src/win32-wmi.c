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

// clang-format off
#include <winsock2.h>
#include <windows.h>
#include <wbemidl.h>
// clang-format on

#include "util-debug.h"
#include "util-device.h"

#include "win32-misc.h"
#include "win32-wmi.h"

#define MAKE_VARIANT(v, type, value)                                           \
    do {                                                                       \
        VARIANT(v);                                                            \
        VariantInit(&(v));                                                     \
        V_VT(&v) = VT_##type;                                                  \
        V_##type##(&v) = value;                                                \
    } while (0);

#define RELEASE_OBJECT(objptr)                                                 \
    do {                                                                       \
        if ((objptr) != NULL) {                                                \
            (objptr)->lpVtbl->Release(objptr);                                 \
        }                                                                      \
    } while (0);

typedef enum Win32TcpOffloadFlags_ {
    WIN32_TCP_OFFLOAD_FLAG_NONE = 0,
    WIN32_TCP_OFFLOAD_FLAG_LSOV1 = 1,
    WIN32_TCP_OFFLOAD_FLAG_LSOV2_IP4 = 1 << 1,
    WIN32_TCP_OFFLOAD_FLAG_LSOV2_IP6 = 1 << 2
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

    BSTR *object_name, *method_name;

    IWbemClassObject *object;
    IWbemClassObject *in_params, *out_params;
} WmiMethod;

/**
 * \brief Releases resources for a WMI method handle
 */
static void WmiMethodRelease(WmiMethod *method)
{
    if (method->object != NULL) {
        method->object->lpVtbl->Release(method->object);
    }
    if (method->in_params != NULL) {
        method->in_params->lpVtbl->Release(method->in_params)
    }
    if (method->out_params != NULL) {
        method->out_params->lpVtbl->Release(method->out_params)
    }
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
    hr = method->com_instance.services->GetObject(
            object_name, WBEM_FLAG_RETURN_WBEM_COMPLETE, NULL, &object, NULL);
    if (hr != WBEM_S_NO_ERROR) {
        SCLogWarning(SC_ERR_SYSCALL, "WMI GetObject failed: 0x%" PRIx32,
                     (uint32_t)hr);
        goto fail;
    }

    /* find the method on the retrieved object */
    hr = method->object->lpVtbl->GetMethod(method_name, 0, &method->in_params,
                                           &method->out_params);
    if (hr != WBEM_S_NO_ERROR) {
        SCLogWarning(SC_ERR_SYSCALL, "WMI GetMethod failed: 0x%" PRIx32,
                     (uint32_t)hr);
        goto fail;
    }

    return S_OK;

fail:
    WmiMethodRelease(&method->com_instance);

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
    hr = method->in_params->lpVtbl->SpawnInstance(0, &call->in_params);
    if (hr != S_OK) {
        SCLogWarning(SC_ERR_SYSCALL,
                     "WMI SpawnInstance failed on in_params: 0x%" PRIx32,
                     (uint32_t)hr);
        goto fail;
    }
    hr = method->out_params->lpVtbl->SpawnInstance(0, &call->out_params);
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

    call->executed = true;

    hr = call->method->com_instance.services->lpVtbl->ExecMethod(
            call->method->object_name, call->method->method_name, 0, NULL,
            call->in_params, &call->out_params, NULL);
    if (hr != WBEM_S_NO_ERROR) {
        SCLogWarning(SC_ERR_SYSCALL, "WMI ExecMethod failed: 0x%" PRIx32,
                     (uint32_t)hr);
        return hr;
    }

    return hr;
}

/**
 * Obtains a
 */
static HRESULT WbemGetSubObject(IWbemClassObject *object, LPCWSTR property_name,
                                IWbemClassObject **sub_object)
{
    HRESULT hr = S_OK;

    MAKE_VARIANT(out_var, UNKNOWN, NULL);

    hr = object->lpVtbl->Get(property_name, 0, &out_var, NULL);
    if (hr != WBEM_S_NO_ERROR) {
        goto release;
    }
    VariantClear(&out_var);
    hr = ((IUnknown)V_UNKNOWN(&out_var))
                 ->lpVtbl->QueryInterface(IID_IWbemClassObject, sub_object);
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
 * \brief polls the NDIS TCP offloading status, namely LSOv1/v2
 */
static HRESULT GetNdisOffload(NET_IFINDEX if_index, uint64_t *offload_flags)
{
    HRESULT hr = S_OK;

    /* namespace, class, function strings */
    LPCWSTR object_name = L"MSNdis_TcpOffloadCurrentConfig";
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
    BSTR ndis_object_header_name = SysAllocString("MSNdis_ObjectHeader");
    if (ndis_object_header_name == NULL) {
        SCLogWarning(SC_ERR_SYSCALL, "Failed to allocate BSTR");
        goto release;
    }
    IWbemClassObject *ndis_object_header;
    hr = method->com_instance.services->lpVtbl->GetObject(
            ndis_object_header_name, WBEM_FLAG_RETURN_WBEM_COMPLETE, NULL,
            &ndis_object_header, NULL);
    if (hr != WBEM_S_NO_ERROR) {
        SCLogWarning(SC_ERR_SYSCALL, "WMI GetObject failed: 0x%" PRIx32,
                     (uint32_t)hr);
        goto release;
    }
    IUnknown *ndis_object_header_unknown;
    hr = ndis_object_header->lpVtbl->QueryInterface(
            IID_IUnknown, &ndis_object_header_unknown);
    if (hr != S_OK) {
        SCLogWarning(SC_ERR_SYSCALL,
                     "WMI QueryInterface (IUnknown) failed: 0x%" PRIx32,
                     (uint32_t)hr);
        goto release;
    }

    /* Set parameters of MSNdis_ObjectHeader */
    MAKE_VARIANT(header_type, UI1, NDIS_WMI_OBJECT_TYPE_METHOD);
    hr = ndis_object_header->lpVtbl->Put(L"Type", 0, header_type);
    if (hr != WBEM_S_NO_ERROR) {
        goto release;
    }
    MAKE_VARIANT(header_revision, UI1, NDIS_GUID_HEADER_REVISION_1);
    hr = ndis_object_header->lpVtbl->Put(L"Revision", 0, header_revision);
    if (hr != WBEM_S_NO_ERROR) {
        goto release;
    }
    MAKE_VARIANT(header_size, UI2, sizeof(NDIS_WMI_OBJECT_TYPE_METHOD));
    hr = ndis_object_header->lpVtbl->Put(L"Size", 0, header_size, VT_UI2);
    if (hr != WBEM_S_NO_ERROR) {
        goto release;
    }

    /* Set values in MSNdis_WmiMethodHeader (in_params) */
    MAKE_VARIANT(ndis_object_header_var, UNKNOWN, ndis_header_object_unknown);
    hr = call->in_params->lpVtbl->Put(L"Header", 0, ndis_object_header_var,
                                      VT_UNKNOWN);
    if (hr != WBEM_S_NO_ERROR) {
        goto release;
    }
    MAKE_VARIANT(net_luid, UI8, 0);
    hr = call->in_params->lpVtbl->Put(L"NetLuid", 0, net_luid, VT_UI8);
    if (hr != WBEM_S_NO_ERROR) {
        goto release;
    }
    MAKE_VARIANT(port_number, UI4, 0);
    hr = call->in_params->lpVtbl->Put(L"PortNumber", 0, port_number, VT_UI4);
    if (hr != WBEM_S_NO_ERROR) {
        goto release;
    }
    MAKE_VARIANT(request_id, UI8, 0);
    hr = call->in_params->lpVtbl->Put(L"RequestId", 0, request_id, VT_UI8);
    if (hr != WBEM_S_NO_ERROR) {
        goto release;
    }
    MAKE_VARIANT(timeout, UI4, 5);
    hr = call->in_params->lpVtbl->Put(L"Timeout", 0, timeout, VT_UI4);
    if (hr != WBEM_S_NO_ERROR) {
        goto release;
    }

    /* execute the method */
    hr = WmiMethodCallExec(&call);
    if (hr != S_OK) {
        goto release;
    }

    /* inspect the result */
    VARIANT out_var;
    VariantInit(&out_var);

    /* LsoV1 */
    IWbemClassObject *lso_v1_object;
    WbemGetSubObject(out_params, L"LsoV1", &lso_v1_object);
    IWbemClassObject *lso_v1_ipv4_object;
    WbemGetSubObject(lso_v1_object, L"WmiIPv4", &lso_v1_ipv4_object);
    hr = lso_v1_ipv4_object->lpVtbl->Get(L"Encapsulation", 0, &out_var, NULL);
    if (hr != WBEM_S_NO_ERROR) {
        goto release;
    }
    if (VT_UI4(&out_var) != 0) { /* encapsulation flags indicate offload */
        *offload_flags |= WIN32_TCP_OFFLOAD_FLAG_LSOV1;
    }

    /* LsoV2 */
    IWbemClassObject *lso_v2_object;
    WbemGetSubObject(out_params, L"LsoV2", &lso_v2_object);
    /* IPv4 */
    IWbemClassObject *lso_v2_ip4_object;
    WbemGetSubObject(lso_v2_object, L"WmiIPv4", &lso_v2_ip4_object);
    VariantClear(&out_var);
    hr = lso_v2_ip4_object->lpVtbl->Get(L"Encapsulation", 0, &out_var, NULL);
    if (hr != WBEM_S_NO_ERROR) {
        goto release;
    }
    if (VT_UI4(&out_var) != 0) { /* encapsulation flags indicate offload */
        *offload_flags |= WIN32_TCP_OFFLOAD_FLAG_LSOV2_IP4;
    }
    /* IPv6 */
    IWbemClassObject *lso_v2_ip6_object;
    WbemGetSubObject(lso_v2_object, L"WmiIPv6", &lso_v2_ip6_object);
    VariantClear(&out_var);
    hr = lso_v2_ip6_object->lpVtbl->Get(L"Encapsulation", 0, &out_var, NULL);
    if (hr != WBEM_S_NO_ERROR) {
        goto release;
    }

    if (VT_UI4(&out_var) != 0) { /* encapsulation flags indicate offload */
        *offload_flags |= WIN32_TCP_OFFLOAD_FLAG_LSOV2_IP6;
    }

release:
    RELEASE_OBJECT(lso_v2_ip6_object);
    RELEASE_OBJECT(lso_v2_ip4_object);
    RELEASE_OBJECT(lso_v2_object);
    RELEASE_OBJECT(lso_v1_ipv4_object);
    RELEASE_OBJECT(lso_v1_object);

    VariantClear(&out_var);
    VariantClear(&timeout);
    VariantClear(&request_id);
    VariantClear(&port_number);
    VariantClear(&net_luid);
    VariantClear(&header_size);
    VariantClear(&header_revision);
    VariantClear(&header_type);
    VariantClear(&ndis_object_header_var);

    if (ndis_object_header != NULL) {
        ndis_object_header->lpVtbl->Release(ndis_object_header);
    }
    SysFreeString(ndis_object_header_name);

    WmiMethodCallRelease(&call);
    WmiMethodRelease(&method);

    return hr;
}

int GetIfaceOffloadingWin32(const char *pcap_dev)
{
    int ret = 0;
    uint64_t offload_flags;

    NET_IFINDEX if_index = if_nametoindex(pcap_dev);

    HRESULT hr = GetNdisOffload(if_index, &offload_flags);
    if (hr != S_OK) {
        ret = -1;
    } else if (offload_flags != 0) {
        ret = 1;
        SCLogWarning(SC_ERR_NIC_OFFLOADING, )
    }

release:
    return ret;
}

int DisableIfaceOffloadingWin32(LiveDevice *ldev) { return 0; }

int RestoreIfaceOffloadingWin32(LiveDevice *ldev) { return 0; }

#endif /* OS_WIN32 */
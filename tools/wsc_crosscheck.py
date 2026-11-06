"""Cross-check the productState decoding against the documented WSC API.

LexShield reads antivirus and firewall state from WMI (root/SecurityCenter2),
whose productState bit field Microsoft does not document. This script asks the
documented interface (IWSCProductList / IWscProduct, wscapi.h) for the same
products, so both readings can be compared on a real machine.

Run on Windows:  python tools/wsc_crosscheck.py
Read-only: it creates the WSC product list object and reads properties.
"""

import ctypes
import sys
import uuid
from ctypes import POINTER, WINFUNCTYPE, byref, c_int, c_long, c_ulong, c_void_p

CLSID_WSC_PRODUCT_LIST = "17072F7B-9ABE-4A74-A261-1EB76B55107A"
IID_IWSC_PRODUCT_LIST = "722A338C-6E8E-4E72-AC27-1417FB0C81C2"
PROVIDERS = {"firewall": 0x1, "antivirus": 0x4}
STATES = {0: "on", 1: "off", 2: "snoozed", 3: "expired"}  # WSC_SECURITY_PRODUCT_STATE
SIGNATURES = {0: "out of date", 1: "up to date"}  # WSC_SECURITY_SIGNATURE_STATUS


class GUID(ctypes.Structure):
    _fields_ = [("bytes", ctypes.c_ubyte * 16)]


def guid(text: str) -> GUID:
    value = GUID()
    ctypes.memmove(byref(value), uuid.UUID(text).bytes_le, 16)
    return value


def method(pointer: c_void_p, index: int, *argtypes):
    """Call a COM method by its vtable index (IDispatch occupies indexes 0-6)."""
    vtable = ctypes.cast(pointer, POINTER(POINTER(c_void_p))).contents
    function = WINFUNCTYPE(ctypes.HRESULT, c_void_p, *argtypes)(vtable[index])
    return lambda *args: function(pointer, *args)


def main() -> int:
    if sys.platform != "win32":
        print("Windows only.")
        return 1
    ole32 = ctypes.OleDLL("ole32")
    ole32.CoInitializeEx(None, 2)
    for label, provider in PROVIDERS.items():
        product_list = c_void_p()
        ole32.CoCreateInstance(
            byref(guid(CLSID_WSC_PRODUCT_LIST)), None, 1, byref(guid(IID_IWSC_PRODUCT_LIST)), byref(product_list)
        )
        method(product_list, 7, c_ulong)(provider)  # Initialize
        count = c_long()
        method(product_list, 8, POINTER(c_long))(byref(count))  # get_Count
        for index in range(count.value):
            product = c_void_p()
            method(product_list, 9, c_ulong, POINTER(c_void_p))(index, byref(product))  # get_Item
            name, state, signatures = ctypes.c_wchar_p(), c_int(), c_int()
            method(product, 7, POINTER(ctypes.c_wchar_p))(byref(name))  # get_ProductName
            method(product, 8, POINTER(c_int))(byref(state))  # get_ProductState
            method(product, 9, POINTER(c_int))(byref(signatures))  # get_SignatureStatus
            print(f"{label:<9} {name.value:<35} {STATES.get(state.value, state.value):<8} "
                  f"signatures {SIGNATURES.get(signatures.value, signatures.value)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

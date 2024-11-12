#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This script analyzes MZ-PE (MS-DOS) executable file
#    Copyright (C) 2023  Maurice Lambert

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
##################

"""
This script analyzes MZ-PE (MS-DOS) executable file.
"""

__version__ = "1.1.1"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = "This script analyzes MZ-PE (MS-DOS) executable."
license = "GPL-3.0 License"
__url__ = "https://github.com/mauricelambert/ProgramExecutableAnalyzer"

copyright = """
ProgramExecutableAnalyzer  Copyright (C) 2023  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
"""
__license__ = license
__copyright__ = copyright

__all__ = []

print(copyright)

from sys import argv, stderr, stdin, exit, executable
from string import printable as printable_
from os.path import basename, isfile
from urllib.request import urlopen
from dataclasses import dataclass
from shutil import copyfileobj
from binascii import hexlify
from os.path import getsize
from random import randint
from typing import Tuple
from io import BytesIO
from time import ctime
from os import name

@dataclass
class Section:
    label: str
    start_position: int
    size: int

try:
    from EntropyAnalysis import charts_chunks_file_entropy, Section
    from matplotlib import pyplot
except ImportError:
    print(
        "EntropyAnalysis is not installed in the python "
        "environment or matplotlib.pyplot cannot be imported."
        " No entropy analysis will run. No plot to compare "
        "sections virtual size/address and physical size/address"
        " will spawn.\n\t - to install EntropyAnalysis and "
        "matplotlib run the following command: pip install"
        " EntropyAnalysis matplotlib\nThis is not requirements"
        " because this script should run on server without any "
        "GUI installed.",
        # file=stderr,
    )
    entropy_charts_import = False
else:
    entropy_charts_import = True

printable = printable_[:-5].encode()
not_printable = [x for x in range(256) if x not in printable]

if "-h" in argv:
    print(
        "USAGES:",
        executable,
        argv[0],
        "[-c(no color)] [-v(verbose)] [-u(url)] "
        "WindowsNativeExecutableFile.exe",
        file=stderr,
    )
    exit(1)
elif "-c" not in argv:
    print_ = print
    print = (
        lambda *x, **y: print_(
            x[0],
            "\x1b[48;2;50;50;50m\x1b[38;2;175;241;11m"
            + str(x[1])
            + "\x1b[49m\x1b[39m",
            x[2],
            **y,
        )
        if len(x) < 4
        else print_(
            "\x1b[38;2;183;121;227m" + x[0],
            "\x1b[38;2;255;240;175m" + x[1],
            "\x1b[38;2;255;208;11m" + x[2],
            "\x1b[38;2;212;171;242m" + x[3] + "\x1b[38;2;201;247;87m",
            *x[4:],
            "\x1b[39m",
            **y,
        )
    )
else:
    argv.remove("-c")


if name == 'nt':
    from ctypes.wintypes import DWORD
    from ctypes import windll, byref, WinDLL

    def active_virtual_terminal() -> bool:
        """
        This function active terminal colors on Windows.

        return True on success and False on fail.

        This function come from: https://raw.githubusercontent.com/mauricelambert/PythonToolsKit/main/PythonToolsKit/WindowsTerminal.py
        doc: https://docs.microsoft.com/fr-fr/windows/console/console-virtual-terminal-sequences#code-try-1

        >>> print("\\x1b[32mabc\\x1b[0m")
        ←[32mabc←[0m
        >>> active_virtual_terminal()
        True
        >>> print("\\x1b[32mabc\\x1b[0m")
        abc
        >>> active_virtual_terminal()
        False
        >>>
        """

        default_in_mode: DWORD = DWORD()
        default_out_mode: DWORD = DWORD()

        kernel32: WinDLL = windll.kernel32
        _FuncPtr: type = kernel32._FuncPtr

        GetStdHandle: _FuncPtr = kernel32.GetStdHandle
        GetConsoleMode: _FuncPtr = kernel32.GetConsoleMode
        SetConsoleMode: _FuncPtr = kernel32.SetConsoleMode

        OUT_ENABLE_VIRTUAL_TERMINAL_PROCESSING: int = 0x0004
        OUT_DISABLE_NEWLINE_AUTO_RETURN: int = 0x0008

        STDOUT: int = GetStdHandle(-11)

        if not GetConsoleMode(STDOUT, byref(default_out_mode)):
            return False

        new_out_mode = (
            OUT_ENABLE_VIRTUAL_TERMINAL_PROCESSING
            | OUT_DISABLE_NEWLINE_AUTO_RETURN
        )

        new_out_mode = DWORD(default_out_mode.value | new_out_mode)

        if not SetConsoleMode(STDOUT, new_out_mode):
            return False

        return True

    active_virtual_terminal()

colors = []


def generate_color() -> Tuple[float, float, float]:
    """
    This function generates different colors for charts.
    """

    red = randint(0, 150) + 50
    blue = randint(0, 128) + 127
    green = randint(0, 150) + 50

    for red_, green_, blue_ in colors:
        if (
            sum(
                (
                    (max(red, red_) - min(red, red_)),
                    (max(green, green_) - min(green, green_)),
                    (max(blue, blue_) - min(blue, blue_)),
                )
            )
            < 50
        ):
            return generate_color()

    colors.append((red, green, blue))
    return (red, green, blue)


# print = lambda *x, **y: None
myCounter = 1

if "-v" in argv:
    argv.remove("-v")
    vprint = print
else:
    vprint = lambda *x, **y: None

if "-u" in argv:
    argv.remove("-u")
    is_url = True
else:
    is_url = False

if len(argv) != 2:
    print(
        "USAGES:",
        executable,
        argv[0],
        "[-c(no color)] [-v(verbose)] [-u(url)] "
        "WindowsNativeExecutableFile.exe",
        file=stderr,
    )
    exit(1)

if is_url:
    try:
        data = urlopen(argv[1]).read()
    except Exception as e:
        print(
            "An exception was raised when request URL:",
            argv[1],
            f"({e.__class__.__name__}: {e})",
            file=stderr,
        )
        exit(2)
elif argv[1] == "-":
    is_url = True
    data = stdin.buffer.read()

if name == "nt" and not is_url:
    from ctypes.wintypes import (
        DWORD,
        LPCWSTR,
        LPVOID,
        BYTE,
        LPSTR,
        LPWSTR,
        BOOL,
        FILETIME,
        WCHAR,
        LPCSTR,
        WORD,
        HANDLE,
    )
    from ctypes import (
        Structure,
        windll,
        sizeof,
        c_ulonglong,
        c_ulong,
        c_ushort,
        c_byte,
        pointer,
        POINTER,
        c_void_p,
        cast,
        c_uint8,
    )

    verify_sign = windll.LoadLibrary("wintrust").WinVerifyTrust
    last_error = windll.LoadLibrary("kernel32").GetLastError
    crypt_query = windll.LoadLibrary("crypt32").CryptQueryObject
    crypt_message = windll.LoadLibrary("crypt32").CryptMsgGetParam
    find_certificate = windll.LoadLibrary("crypt32").CertFindCertificateInStore
    get_certificate_name = windll.LoadLibrary("crypt32").CertGetNameStringA
    crypt_decode = windll.LoadLibrary("crypt32").CryptDecodeObject
    time_to_localtime = windll.LoadLibrary("kernel32").FileTimeToLocalFileTime
    time_to_systemtime = windll.LoadLibrary("kernel32").FileTimeToSystemTime
    alloc = windll.LoadLibrary("kernel32").LocalAlloc

    class GUID(Structure):
        _fields_ = [
            ("data1", c_ulong),
            ("data2", c_ushort),
            ("data3", c_ushort),
            ("data4", c_byte * 8),
        ]

    class WINTRUST_FILE_INFO(Structure):
        _fields_ = [
            ("cbStruct", DWORD),
            ("pcwszFilePath", LPCWSTR),
            ("hFile", HANDLE),
            ("pgKnownSubject", LPVOID),
        ]

    class WINTRUST_DATA(Structure):
        _fields_ = [
            ("cbStruct", DWORD),
            ("pPolicyCallbackData", LPVOID),
            ("pSIPClientData", LPVOID),
            ("dwUIChoice", DWORD),
            ("fdwRevocationChecks", DWORD),
            ("dwUnionChoice", DWORD),
            ("pFile", POINTER(WINTRUST_FILE_INFO)),
            ("dwStateAction", DWORD),
            ("hWVTStateData", HANDLE),
            ("pwszURLReference", LPCWSTR),
            ("dwProvFlags", DWORD),
            ("dwUIContext", DWORD),
            ("pSignatureSettings", LPVOID),
        ]

    class SPC_LINK(Structure):
        _fields_ = [
            ("dwLinkChoice", DWORD),
            ("pwszFile", LPWSTR),
        ]

    class SPC_SP_OPUS_INFO(Structure):
        _fields_ = [
            ("pwszProgramName", LPCWSTR),
            ("pMoreInfo", POINTER(SPC_LINK)),
            ("pPublisherInfo", POINTER(SPC_LINK)),
        ]

    class CRYPTOAPI_BLOB(Structure):
        _fields_ = [
            ("cbData", DWORD),
            ("pbData", POINTER(BYTE)),
        ]

    class CRYPT_ATTRIBUTE(Structure):
        _fields_ = [
            ("pszObjId", LPSTR),
            ("cValue", DWORD),
            ("rgValue", POINTER(CRYPTOAPI_BLOB)),
        ]

    class CRYPT_ATTRIBUTES(Structure):
        _fields_ = [
            ("cAttr", DWORD),
            ("rgAttr", POINTER(CRYPT_ATTRIBUTE)),
        ]

    class CRYPT_ALGORITHM_IDENTIFIER(Structure):
        _fields_ = [
            ("pszObjId", LPSTR),
            ("Parameters", CRYPTOAPI_BLOB),
        ]

    class CMSG_SIGNER_INFO(Structure):
        _fields_ = [
            ("dwVersion", DWORD),
            ("Issuer", CRYPTOAPI_BLOB),
            ("SerialNumber", CRYPTOAPI_BLOB),
            ("HashAlgorithm", CRYPT_ALGORITHM_IDENTIFIER),
            ("HashEncryptionAlgorithm", CRYPT_ALGORITHM_IDENTIFIER),
            ("EncryptedHash", CRYPTOAPI_BLOB),
            ("AuthAttrs", CRYPT_ATTRIBUTES),
            ("UnauthAttrs", CRYPT_ATTRIBUTES),
        ]

    class CRYPT_BIT_BLOB(Structure):
        _fields_ = [
            ("cbData", DWORD),
            ("pbData", POINTER(BYTE)),
            ("cUnusedBits", DWORD),
        ]

    class CERT_EXTENSION(Structure):
        _fields_ = [
            ("pszObjId", LPSTR),
            ("fCritical", BOOL),
            ("Value", CRYPTOAPI_BLOB),
        ]

    class CERT_PUBLIC_KEY_INFO(Structure):
        _fields_ = [
            ("Algorithm", CRYPT_ALGORITHM_IDENTIFIER),
            ("PublicKey", CRYPT_BIT_BLOB),
        ]

    class CERT_INFO(Structure):
        _fields_ = [
            ("dwVersion", DWORD),
            ("SerialNumber", CRYPTOAPI_BLOB),
            ("SignatureAlgorithm", CRYPT_ALGORITHM_IDENTIFIER),
            ("Issuer", CRYPTOAPI_BLOB),
            ("NotBefore", FILETIME),
            ("NotAfter", FILETIME),
            ("Subject", CRYPTOAPI_BLOB),
            ("SubjectPublicKeyInfo", CERT_PUBLIC_KEY_INFO),
            ("IssuerUniqueId", CRYPT_BIT_BLOB),
            ("SubjectUniqueId", CRYPT_BIT_BLOB),
            ("cExtension", DWORD),
            ("rgExtension", POINTER(CERT_EXTENSION)),
        ]

    class CERT_CONTEXT(Structure):
        _fields_ = [
            ("dwCertEncodingType", DWORD),
            ("pbCertEncoded", POINTER(BYTE)),
            ("cbCertEncoded", DWORD),
            ("pCertInfo", POINTER(CERT_INFO)),
            ("hCertStore", LPVOID),
        ]

    class SYSTEMTIME(Structure):
        _fields_ = [
            ("wYear", WORD),
            ("wMonth", WORD),
            ("wDayOfWeek", WORD),
            ("wDay", WORD),
            ("wHour", WORD),
            ("wMinute", WORD),
            ("wSecond", WORD),
            ("wMilliseconds", WORD),
        ]

    WINTRUST_ACTION_GENERIC_VERIFY_V2 = GUID(
        0xAAC56B,
        0xCD44,
        0x11D0,
        (0x8C, 0xC2, 0x0, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
    )
    wintrust = WINTRUST_DATA(
        sizeof(WINTRUST_DATA),
        0,
        0,
        2,
        0,
        1,
        pointer(WINTRUST_FILE_INFO(sizeof(WINTRUST_FILE_INFO), argv[1], 0, 0)),
        1,
        0,
        0,
        0,
        0,
        0,
    )
    verify_sign.restype = c_ulonglong
    last_error.restype = c_ulonglong
    status = verify_sign(
        0, pointer(WINTRUST_ACTION_GENERIC_VERIFY_V2), pointer(wintrust)
    )
    if not status:
        print(
            "",
            f'[+] The file "{argv[1]}" is signed and the signature was verified.',
            "",
        )
    elif status == 0x800B0100:
        err = last_error()
        if err in (0x800B0100, 0x800B0003, 0x800B0001):
            print_(f'\x1b[33m[-] The file "{argv[1]}" is not signed.\x1b[0m')
        else:
            print_(
                f'\x1b[31m[!] An unknown error occurred trying to verify the signature of the "{argv[1]}" file.\x1b[0m'
            )
    elif status == 0x800B0111:
        print_("\x1b[33m[-] The signature is present, but not trusted.\x1b[0m")
    elif status == 0x80092026:
        print_(
            "\x1b[33m[-] CRYPT_E_SECURITY_SETTINGS - The hash representing the subject or the publisher wasn't explicitly trusted by the admin and admin policy has disabled user trust. No signature, publisher or timestamp errors.\x1b[0m"
        )
    else:
        print_("\x1b[31m[!] Verify signature error is:", status, "\x1b[0m")
    wintrust.dwStateAction = 2
    status2 = verify_sign(
        0, pointer(WINTRUST_ACTION_GENERIC_VERIFY_V2), pointer(wintrust)
    )
else:
    print_(
        "Cannot check the siganture on Linux or from URL or STDIN", file=stderr
    )
    status = None

if status in (0, 0x800B0111):
    dword_encoding = DWORD()
    dword_contenttype = DWORD()
    dword_formattype = DWORD()
    store = LPVOID()
    message = LPVOID()
    dword_signerinfo = DWORD()

    result = crypt_query(
        1,
        argv[1],
        1024,
        2,
        0,
        pointer(dword_encoding),
        pointer(dword_contenttype),
        pointer(dword_formattype),
        pointer(store),
        pointer(message),
        0,
    )

    if not result:
        print_("CryptQueryObject failed with", last_error(), file=stderr)

    result = crypt_message(message, 6, 0, 0, pointer(dword_signerinfo))

    if not result:
        print_("CryptMsgGetParam failed with", last_error(), file=stderr)

    alloc.restype = c_void_p
    signerinfo = cast(
        alloc(0x0040, dword_signerinfo), POINTER(CMSG_SIGNER_INFO)
    )

    if not signerinfo:
        print_("Unable to allocate memory for Signer Info.", file=stderr)

    result = crypt_message(
        message, 6, 0, signerinfo, pointer(dword_signerinfo)
    )

    if not result:
        print_("CryptMsgGetParam failed with", last_error(), file=stderr)

    for i in range(signerinfo.contents.AuthAttrs.cAttr):
        dword_data = DWORD()
        if (
            signerinfo.contents.AuthAttrs.rgAttr[i].pszObjId
            == b"1.3.6.1.4.1.311.2.1.12"
        ):
            result = crypt_decode(
                65537,
                b"1.3.6.1.4.1.311.2.1.12",
                signerinfo.contents.AuthAttrs.rgAttr[i].rgValue[0].pbData,
                signerinfo.contents.AuthAttrs.rgAttr[i].rgValue[0].cbData,
                0,
                0,
                pointer(dword_data),
            )
            if not result:
                print_(
                    "CryptDecodeObject failed with", last_error(), file=stderr
                )

            publisherinfo = cast(
                alloc(0x0040, dword_data), POINTER(SPC_SP_OPUS_INFO)
            )
            if not publisherinfo:
                print_(
                    "Unable to allocate memory for Publisher Info.",
                    file=stderr,
                )

            result = crypt_decode(
                65537,
                b"1.3.6.1.4.1.311.2.1.12",
                signerinfo.contents.AuthAttrs.rgAttr[i].rgValue[0].pbData,
                signerinfo.contents.AuthAttrs.rgAttr[i].rgValue[0].cbData,
                0,
                publisherinfo,
                pointer(dword_data),
            )

            if not result:
                print_(
                    "CryptDecodeObject failed with", last_error(), file=stderr
                )

            print(
                "",
                "    - Program Name: "
                + str(publisherinfo.contents.pwszProgramName),
                "",
            )

            if publisherinfo.contents.pPublisherInfo:
                print(
                    "",
                    "    - Publisher Link: "
                    + publisherinfo.contents.pPublisherInfo.contents.pwszFile,
                    "",
                )

            if publisherinfo.contents.pMoreInfo:
                print(
                    "",
                    "    - MoreInfo Link:"
                    + publisherinfo.contents.pMoreInfo.contents.pwszFile,
                    "",
                )
            break

    cert_info = CERT_INFO()
    cert_info.Issuer = signerinfo.contents.Issuer
    cert_info.SerialNumber = signerinfo.contents.SerialNumber

    find_certificate.restype = POINTER(CERT_CONTEXT)
    cert_context = find_certificate(
        store, 65537, 0, 720896, pointer(cert_info), 0
    )
    if not cert_context:
        print_(
            "CertFindCertificateInStore failed with", last_error(), file=stderr
        )

    print("", "    - Signer Certificate:", "")
    serial_number = cast(
        cert_context.contents.pCertInfo.contents.SerialNumber.pbData,
        POINTER(c_uint8),
    )
    print(
        "",
        "        - Serial Number: "
        + " ".join(
            f"{serial_number[i]:0>2x}"
            for i in range(
                cert_context.contents.pCertInfo.contents.SerialNumber.cbData
                - 1,
                -1,
                -1,
            )
        ),
        "",
    )

    dword_data = get_certificate_name(cert_context, 4, 1, 0, 0, 0)

    if not dword_data:
        print_("CertGetNameString failed.")

    name = cast(alloc(0x0040, dword_data * sizeof(WCHAR)), LPSTR)
    if not name:
        print_("Unable to allocate memory for issuer name.")

    dword_data = get_certificate_name(cert_context, 4, 1, 0, name, dword_data)
    if not dword_data:
        print_("CertGetNameString failed.")

    print("", "        - Issuer Name: ".ljust(25) + name.value.decode(), "")

    dword_data = get_certificate_name(cert_context, 4, 0, 0, 0, 0)

    if not dword_data:
        print_("CertGetNameString failed.")

    name = cast(alloc(0x0040, dword_data * sizeof(WCHAR)), LPSTR)
    if not name:
        print_("Unable to allocate memory for issuer name.")

    dword_data = get_certificate_name(cert_context, 4, 0, 0, name, dword_data)
    if not dword_data:
        print_("CertGetNameString failed.")

    print("", "        - Subject Name: ".ljust(25) + name.value.decode(), "")

    temp_filetime = FILETIME()
    systemtime = SYSTEMTIME()
    time_to_localtime(
        pointer(cert_context.contents.pCertInfo.contents.NotBefore),
        pointer(temp_filetime),
    )
    time_to_systemtime(pointer(temp_filetime), pointer(systemtime))

    print(
        "",
        "        - Valid from: ".ljust(25)
        + str(systemtime.wYear)
        + "-"
        + f"{systemtime.wMonth:0>2}"
        + "-"
        + f"{systemtime.wDay:0>2}"
        + " "
        + f"{systemtime.wHour:0>2}"
        + ":"
        + f"{systemtime.wMinute:0>2}"
        + ":"
        + f"{systemtime.wSecond:0>2}"
        + "."
        + str(systemtime.wMilliseconds),
        "",
    )

    temp_filetime = FILETIME()
    systemtime = SYSTEMTIME()
    time_to_localtime(
        pointer(cert_context.contents.pCertInfo.contents.NotAfter),
        pointer(temp_filetime),
    )
    time_to_systemtime(pointer(temp_filetime), pointer(systemtime))

    print(
        "",
        "        - Valid to: ".ljust(25)
        + str(systemtime.wYear)
        + "-"
        + f"{systemtime.wMonth:0>2}"
        + "-"
        + f"{systemtime.wDay:0>2}"
        + " "
        + f"{systemtime.wHour:0>2}"
        + ":"
        + f"{systemtime.wMinute:0>2}"
        + ":"
        + f"{systemtime.wSecond:0>2}"
        + "."
        + str(systemtime.wMilliseconds),
        "",
    )

    public_key = cast(
        cert_context.contents.pCertInfo.contents.SubjectPublicKeyInfo.PublicKey.pbData,
        POINTER(c_uint8),
    )
    print(
        "",
        "        - Public key: ".ljust(25)
        + " ".join(
            f"{serial_number[i]:0>2x}"
            for i in range(
                cert_context.contents.pCertInfo.contents.SubjectPublicKeyInfo.PublicKey.cbData
                - 1,
                -1,
                -1,
            )
        ),
        "",
    )

    for i in range(signerinfo.contents.UnauthAttrs.cAttr):
        dword_data = DWORD()
        if (
            b"1.2.840.113549.1.9.6"
            == signerinfo.contents.UnauthAttrs.rgAttr[i].pszObjId
        ):
            result = crypt_decode(
                65537,
                LPCSTR(500),
                signerinfo.contents.UnauthAttrs.rgAttr[i].rgValue[0].pbData,
                signerinfo.contents.UnauthAttrs.rgAttr[i].rgValue[0].cbData,
                0,
                0,
                pointer(dword_data),
            )
            if not result:
                print_(
                    "CryptDecodeObject failed with", last_error(), file=stderr
                )

            count_signerinfo = cast(
                alloc(0x0040, dword_data), POINTER(CMSG_SIGNER_INFO)
            )
            if not count_signerinfo:
                print_("Unable to allocate memory for timestamp info.")

            result = crypt_decode(
                65537,
                LPCSTR(500),
                signerinfo.contents.UnauthAttrs.rgAttr[i].rgValue[0].pbData,
                signerinfo.contents.UnauthAttrs.rgAttr[i].rgValue[0].cbData,
                0,
                count_signerinfo,
                pointer(dword_data),
            )
            if not result:
                print_(
                    "CryptDecodeObject failed with", last_error(), file=stderr
                )

            cert_info.Issuer = count_signerinfo.contents.Issuer
            cert_info.SerialNumber = count_signerinfo.contents.SerialNumber

            cert_context = find_certificate(
                store, 65537, 0, 720896, pointer(cert_info), 0
            )

            try:
                cert_context.contents
            except ValueError:
                print_(
                    "CertFindCertificateInStore failed with",
                    last_error(),
                    file=stderr,
                )
                continue

            print("", "     - TimeStamp Certificate:", "")
            serial_number = cast(
                cert_context.contents.pCertInfo.contents.SerialNumber.pbData,
                POINTER(c_uint8),
            )
            print(
                "",
                "        - Serial Number: ".ljust(25)
                + " ".join(
                    f"{serial_number[i]:0>2x}"
                    for i in range(
                        cert_context.contents.pCertInfo.contents.SerialNumber.cbData
                        - 1,
                        -1,
                        -1,
                    )
                ),
                "",
            )

            dword_data = get_certificate_name(cert_context, 4, 1, 0, 0, 0)

            if not dword_data:
                print_("CertGetNameString failed.")

            name = cast(alloc(0x0040, dword_data * sizeof(WCHAR)), LPSTR)
            if not name:
                print_("Unable to allocate memory for issuer name.")

            dword_data = get_certificate_name(
                cert_context, 4, 1, 0, name, dword_data
            )
            if not dword_data:
                print_("CertGetNameString failed.")

            print(
                "",
                "        - Issuer Name: ".ljust(25) + name.value.decode(),
                "",
            )

            dword_data = get_certificate_name(cert_context, 4, 0, 0, 0, 0)

            if not dword_data:
                print_("CertGetNameString failed.")

            name = cast(alloc(0x0040, dword_data * sizeof(WCHAR)), LPSTR)
            if not name:
                print_("Unable to allocate memory for issuer name.")

            dword_data = get_certificate_name(
                cert_context, 4, 0, 0, name, dword_data
            )
            if not dword_data:
                print_("CertGetNameString failed.")

            print(
                "",
                "        - Subject Name: ".ljust(25) + name.value.decode(),
                "",
            )

            temp_filetime = FILETIME()
            systemtime = SYSTEMTIME()
            time_to_localtime(
                pointer(cert_context.contents.pCertInfo.contents.NotBefore),
                pointer(temp_filetime),
            )
            time_to_systemtime(pointer(temp_filetime), pointer(systemtime))

            print(
                "",
                "        - Valid from: ".ljust(25)
                + str(systemtime.wYear)
                + "-"
                + f"{systemtime.wMonth:0>2}"
                + "-"
                + f"{systemtime.wDay:0>2}"
                + " "
                + f"{systemtime.wHour:0>2}"
                + ":"
                + f"{systemtime.wMinute:0>2}"
                + ":"
                + f"{systemtime.wSecond:0>2}"
                + "."
                + str(systemtime.wMilliseconds),
                "",
            )

            temp_filetime = FILETIME()
            systemtime = SYSTEMTIME()
            time_to_localtime(
                pointer(cert_context.contents.pCertInfo.contents.NotAfter),
                pointer(temp_filetime),
            )
            time_to_systemtime(pointer(temp_filetime), pointer(systemtime))

            print(
                "",
                "        - Valid to: ".ljust(25)
                + str(systemtime.wYear)
                + "-"
                + f"{systemtime.wMonth:0>2}"
                + "-"
                + f"{systemtime.wDay:0>2}"
                + " "
                + f"{systemtime.wHour:0>2}"
                + ":"
                + f"{systemtime.wMinute:0>2}"
                + ":"
                + f"{systemtime.wSecond:0>2}"
                + "."
                + str(systemtime.wMilliseconds),
                "",
            )

            public_key = cast(
                cert_context.contents.pCertInfo.contents.SubjectPublicKeyInfo.PublicKey.pbData,
                POINTER(c_uint8),
            )
            print(
                "",
                "        - Public key: ".ljust(25)
                + " ".join(
                    f"{serial_number[i]:0>2x}"
                    for i in range(
                        cert_context.contents.pCertInfo.contents.SubjectPublicKeyInfo.PublicKey.cbData
                        - 1,
                        -1,
                        -1,
                    )
                ),
                "",
            )

            for i in range(count_signerinfo.contents.AuthAttrs.cAttr):
                if (
                    count_signerinfo.contents.AuthAttrs.rgAttr[i].pszObjId
                    == b"1.2.840.113549.1.9.5"
                ):
                    filetime = FILETIME()
                    lfiletime = FILETIME()
                    systemtime = SYSTEMTIME()
                    dword_data = c_ulonglong(sizeof(filetime))
                    result = crypt_decode(
                        65537,
                        b"1.2.840.113549.1.9.5",
                        count_signerinfo.contents.AuthAttrs.rgAttr[i]
                        .rgValue[0]
                        .pbData,
                        count_signerinfo.contents.AuthAttrs.rgAttr[i]
                        .rgValue[0]
                        .cbData,
                        0,
                        pointer(filetime),
                        pointer(dword_data),
                    )
                    if not result:
                        print_(
                            "CryptDecodeObject failed with",
                            last_error(),
                            file=stderr,
                        )

                    time_to_localtime(pointer(filetime), pointer(lfiletime))
                    time_to_systemtime(pointer(lfiletime), pointer(systemtime))

                    print(
                        "",
                        "        - Date of TimeStamp: ".ljust(25)
                        + str(systemtime.wYear)
                        + "-"
                        + f"{systemtime.wMonth:0>2}"
                        + "-"
                        + f"{systemtime.wDay:0>2}"
                        + " "
                        + f"{systemtime.wHour:0>2}"
                        + ":"
                        + f"{systemtime.wMinute:0>2}"
                        + ":"
                        + f"{systemtime.wSecond:0>2}"
                        + "."
                        + str(systemtime.wMilliseconds),
                        "",
                    )

print_()

sections = []
filesize = len(data) if is_url else getsize(argv[1])
with BytesIO(data) if is_url else open(argv[1], "rb") as file:
    print(
        "Data name".ljust(25),
        "Position".ljust(20),
        "Data hexadecimal".ljust(40),
        "Data".ljust(20),
        "Information".ljust(30),
    )
    print("\n", f"{' DOS Headers ':*^139}", "\n", sep="")
    data = file.read(2)
    if data != b"MZ":
        print(
            "",
            "Mark Zbikowski magic (MZ) not found ! Is"
            " not a DOS native executable.",
            "",
            sep="",
            file=stderr,
        )
        exit(2)
    print(
        "Magic".ljust(25),
        f"{0:0>8x}-{2:0>8x}".ljust(20),
        hexlify(data).decode().ljust(40),
        "".join(chr(x) if x in printable else "." for x in data).ljust(20),
        "Mark Zbikowski magic (MZ)",
    )
    data = file.read(2)
    print(
        "Bytes on last page".ljust(25),
        f"{2:0>8x}-{4:0>8x}".ljust(20),
        hexlify(data).decode().ljust(40),
        "".join(chr(x) if x in printable else "." for x in data).ljust(20),
        "Bytes in last page:",
        int.from_bytes(data, "little"),
    )
    data = file.read(2)
    print(
        "Pages in file".ljust(25),
        f"{4:0>8x}-{6:0>8x}".ljust(20),
        hexlify(data).decode().ljust(40),
        "".join(chr(x) if x in printable else "." for x in data).ljust(20),
        int.from_bytes(data, "little"),
        "pages in file.",
    )
    data = file.read(2)
    print(
        "Relocations".ljust(25),
        f"{6:0>8x}-{8:0>8x}".ljust(20),
        hexlify(data).decode().ljust(40),
        "".join(chr(x) if x in printable else "." for x in data).ljust(20),
        int.from_bytes(data, "little"),
        "relocations.",
    )
    data = file.read(2)
    print(
        "Size of header".ljust(25),
        f"{8:0>8x}-{10:0>8x}".ljust(20),
        hexlify(data).decode().ljust(40),
        "".join(chr(x) if x in printable else "." for x in data).ljust(20),
        "MSDOS header file",
        int.from_bytes(data, "little"),
    )
    data = file.read(2)
    vprint(
        "Min extra paragraphs".ljust(25),
        f"{10:0>8x}-{12:0>8x}".ljust(20),
        hexlify(data).decode().ljust(40),
        "".join(chr(x) if x in printable else "." for x in data).ljust(20),
        "minimum paragraphs:",
        int.from_bytes(data, "little"),
    )
    data = file.read(2)
    vprint(
        "Max extra paragraphs".ljust(25),
        f"{12:0>8x}-{14:0>8x}".ljust(20),
        hexlify(data).decode().ljust(40),
        "".join(chr(x) if x in printable else "." for x in data).ljust(20),
        "maximum paragraphs:",
        int.from_bytes(data, "little"),
    )
    data = file.read(2)
    print(
        "Initial SS value".ljust(25),
        f"{14:0>8x}-{16:0>8x}".ljust(20),
        hexlify(data).decode().ljust(40),
        "".join(chr(x) if x in printable else "." for x in data).ljust(20),
        "Stack segment module:",
        int.from_bytes(data, "little"),
    )
    data = file.read(2)
    print(
        "Initial SP value".ljust(25),
        f"{16:0>8x}-{18:0>8x}".ljust(20),
        hexlify(data).decode().ljust(40),
        "".join(chr(x) if x in printable else "." for x in data).ljust(20),
        "SP register:",
        int.from_bytes(data, "little"),
    )
    data = file.read(2)
    vprint(
        "Checksum".ljust(25),
        f"{18:0>8x}-{20:0>8x}".ljust(20),
        hexlify(data).decode().ljust(40),
        "".join(chr(x) if x in printable else "." for x in data).ljust(20),
    )
    data = file.read(2)
    print(
        "Initial IP value".ljust(25),
        f"{20:0>8x}-{22:0>8x}".ljust(20),
        hexlify(data).decode().ljust(40),
        "".join(chr(x) if x in printable else "." for x in data).ljust(20),
        "IP register:",
        int.from_bytes(data, "little"),
    )
    data = file.read(2)
    print(
        "Initial CS value".ljust(25),
        f"{22:0>8x}-{24:0>8x}".ljust(20),
        hexlify(data).decode().ljust(40),
        "".join(chr(x) if x in printable else "." for x in data).ljust(20),
        "CS relative position:",
        int.from_bytes(data, "little"),
    )
    data = file.read(2)
    print(
        "Address of relocation".ljust(25),
        f"{24:0>8x}-{26:0>8x}".ljust(20),
        hexlify(data).decode().ljust(40),
        "".join(chr(x) if x in printable else "." for x in data).ljust(20),
        "Offset relocation table:",
        int.from_bytes(data, "little"),
    )
    data = file.read(2)
    print(
        "Overlay number".ljust(25),
        f"{26:0>8x}-{28:0>8x}".ljust(20),
        hexlify(data).decode().ljust(40),
        "".join(chr(x) if x in printable else "." for x in data).ljust(20),
        "Main executable"
        if int.from_bytes(data, "little") == 0
        else "Not the main executable",
    )
    data = file.read(8)
    vprint(
        "Reserved words".ljust(25),
        f"{28:0>8x}-{36:0>8x}".ljust(20),
        hexlify(data).decode().ljust(40),
        "".join(chr(x) if x in printable else "." for x in data).ljust(20),
        "Extra overlay informations",
    )
    data = file.read(2)
    vprint(
        "OEM identifier".ljust(25),
        f"{36:0>8x}-{38:0>8x}".ljust(20),
        hexlify(data).decode().ljust(40),
        "".join(chr(x) if x in printable else "." for x in data).ljust(20),
    )
    data = file.read(2)
    vprint(
        "OEM information".ljust(25),
        f"{38:0>8x}-{40:0>8x}".ljust(20),
        hexlify(data).decode().ljust(40),
        "".join(chr(x) if x in printable else "." for x in data).ljust(20),
    )
    data = file.read(20)
    vprint(
        "Reserved words".ljust(25),
        f"{40:0>8x}-{60:0>8x}".ljust(20),
        hexlify(data).decode().ljust(40),
        "".join(chr(x) if x in printable else "." for x in data).ljust(20),
    )
    data = file.read(4)
    pe_address = int.from_bytes(data, "little")
    print(
        "Address PE magic bytes".ljust(25),
        f"{60:0>8x}-{64:0>8x}".ljust(20),
        hexlify(data).decode().ljust(40),
        "".join(chr(x) if x in printable else "." for x in data).ljust(20),
        "PE offset:",
        pe_address,
    )
    file.seek(0)
    data = file.read(pe_address)
    end_position = data.find(b"Rich") + 4
    if end_position != -1:
        print("\n", f"{' Rich Headers ':*^139}", "\n", sep="")
        checksum = data[end_position : end_position + 4]
        checksum_value = int.from_bytes(checksum, "little")
        print(
            "Checksum".ljust(25),
            f"{end_position:0>8x}-{end_position+4:0>8x}".ljust(
                20
            ),
            hexlify(checksum).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in checksum).ljust(
                20
            ),
            str(checksum_value),
        )
        marker = bytes(
            reversed(
                bytes(
                    char ^ b"SnaD"[i]
                    for i, char in enumerate(reversed(checksum))
                )
            )
        )
        vprint(
            "Marker".ljust(25),
            f"{end_position:0>8x}-{end_position+4:0>8x}".ljust(
                20
            ),
            hexlify(marker).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in marker).ljust(
                20
            ),
            "",
        )
        start_position = data.find(marker)
        if start_position != -1:
            ids = {
                int.from_bytes(data[i : i + 4], "little")
                ^ checksum_value: int.from_bytes(data[i + 4 : i + 8], "little")
                ^ checksum_value
                for i in range(start_position + 16, end_position - 4, 8)
            }
            calcul_checksum = start_position
            for i, char in enumerate(data[:start_position]):
                if 60 <= i < 64:
                    continue
                calcul_checksum += (char << (i % 32)) | (
                    char >> (32 - (i % 32))
                ) & 255
                calcul_checksum &= 4294967295
            for k, v in ids.items():
                calcul_checksum += k << v % 32 | k >> (32 - (v % 32))
                calcul_checksum &= 4294967295
            print(
                "Calcul checksum".ljust(25),
                f"{end_position:0>8x}-{end_position+4:0>8x}".ljust(
                    20
                ),
                hexlify(calcul_checksum.to_bytes(4)).decode().ljust(40),
                "".join(
                    chr(x) if x in printable else "."
                    for x in calcul_checksum.to_bytes(4)
                ).ljust(20),
                "Valid checksum"
                if calcul_checksum == checksum_value
                else "Invalid checksum",
            )
            if not isfile("rich_ids.txt"):
                with open("rich_ids.txt", "wb") as rich_headers:
                    copyfileobj(
                        urlopen(
                            "https://raw.githubusercontent.com/dishather/richprint/master/comp_id.txt"
                        ),
                        rich_headers,
                    )
            with open("rich_ids.txt") as rich_headers:
                for id_, value in sorted(ids.items(), key=lambda x: x[1]):
                    for line in rich_headers:
                        if line.startswith(f"{id_:0>8x} "):
                            print(
                                "Rich header".ljust(25),
                                f"{start_position:0>8x}-{end_position:0>8x}".ljust(
                                    20
                                ),
                                hexlify(id_.to_bytes(4)).decode().ljust(40),
                                "".join(
                                    chr(x) if x in printable else "."
                                    for x in id_.to_bytes(4)
                                ).ljust(20),
                                line[9:].strip(),
                            )
                    rich_headers.seek(0)
    address = pe_address
    file.seek(pe_address)
    print("\n", f"{' NT Headers ':*^139}", "\n", sep="")
    data = file.read(4)
    if data != b"PE\x00\x00":
        print(
            "",
            "Program Executable magic (PE) not found !"
            " Is not a DOS native executable.",
            "",
            sep="",
            file=stderr,
        )
        exit(2)
    print(
        "PE magic bytes".ljust(25),
        f"{address:0>8x}-{address+4:0>8x}".ljust(20),
        hexlify(data).decode().ljust(40),
        "".join(chr(x) if x in printable else "." for x in data).ljust(20),
        "Program Executable magic (PE)",
    )
    print("\n", f"{' File Headers ':*^139}", "\n", sep="")
    data = file.read(2)
    if data == b"\x64\x86":
        machine = "AMD64 (K8)"
    elif data == b"\x4c\x01":
        machine = "Intel I386/I486/I586"
    elif data == b"\x4d\x01":
        machine = "Intel i860"
    elif (
        data == b"\x62\x01"
        or data == b"\x66\x01"
        or data == b"\x68\x01"
        or data == b"\x69\x01"
    ):
        machine = "MIPS little-endian"
    elif data == b"\x60\x01":
        machine = "MIPS big"
    elif data == b"\x01\x00":
        machine = "Host - no WOW64 Guest"
    elif data == b"\x84\x01":
        machine = "Alpha_AXP"
    elif data == b"\xa2\x01":
        machine = "SH3 little-endian"
    elif data == b"\xa3\x01":
        machine = "SH3DSP"
    elif data == b"\xa4\x01":
        machine = "SH3E little-endian"
    elif data == b"\xa6\x01":
        machine = "SH4 little-endian"
    elif data == b"\xa8\x01":
        machine = "SH5"
    elif data == b"\xc0\x01":
        machine = "ARM Little-Endian"
    elif data == b"\xc2\x01":
        machine = "ARM Thumb/Thumb-2 Little-Endian"
    elif data == b"\xc4\x01":
        machine = "ARM Thumb-2 Little-Endian"
    elif data == b"\xd3\x01":
        machine = "TAM33BD"
    elif data == b"\xf0\x01":
        machine = "IBM PowerPC Little-Endian"
    elif data == b"\xf1\x01":
        machine = "POWERPCFP"
    elif data == b"\x00\x02":
        machine = "Intel 64"
    elif data == b"\x66\x02" or data == b"\x66\x03" or data == b"\x66\x04":
        machine = "MIPS"
    elif data == b"\x84\x02":
        machine = "ALPHA64"
    elif data == b"\x84\x02":
        machine = "AXP64"
    elif data == b"\x20\x05":
        machine = "Infineon"
    elif data == b"\xef\x0c":
        machine = "CEF"
    elif data == b"\xbc\x0e":
        machine = "EFI Byte Code"
    elif data == b"\x41\x90":
        machine = "M32R little-endian"
    elif data == b"\x64\xaa":
        machine = "ARM64 Little-Endian"
    elif data == b"\xee\xc0":
        machine = "CEE"
    else:
        print(
            "Unknow machine value:",
            hexlify(data).decode(),
            "(should be 4C01 or 6486)",
            file=stderr,
        )
        machine = "Unknow"
    print(
        "Machine".ljust(25),
        f"{address+4:0>8x}-{address+6:0>8x}".ljust(20),
        hexlify(data).decode().ljust(40),
        "".join(chr(x) if x in printable else "." for x in data).ljust(20),
        machine,
    )
    data = file.read(2)
    section_number = int.from_bytes(data, "little")
    print(
        "Number of sections".ljust(25),
        f"{address+6:0>8x}-{address+8:0>8x}".ljust(20),
        hexlify(data).decode().ljust(40),
        "".join(chr(x) if x in printable else "." for x in data).ljust(20),
        section_number,
        "sections",
    )
    data = file.read(4)
    print(
        "DateTimeStamp".ljust(25),
        f"{address+8:0>8x}-{address+12:0>8x}".ljust(20),
        hexlify(data).decode().ljust(40),
        "".join(chr(x) if x in printable else "." for x in data).ljust(20),
        ctime(int.from_bytes(data, "little")),
    )
    data = file.read(4)
    vprint(
        "Symbol table address".ljust(25),
        f"{address+12:0>8x}-{address+16:0>8x}".ljust(20),
        hexlify(data).decode().ljust(40),
        "".join(chr(x) if x in printable else "." for x in data).ljust(20),
        "Symbol table address:",
        int.from_bytes(data, "little"),
    )
    data = file.read(4)
    vprint(
        "Number of symbols".ljust(25),
        f"{address+16:0>8x}-{address+20:0>8x}".ljust(20),
        hexlify(data).decode().ljust(40),
        "".join(chr(x) if x in printable else "." for x in data).ljust(20),
        int.from_bytes(data, "little"),
        "symbols.",
    )
    data = file.read(2)
    optional_headers_size = int.from_bytes(data, "little")
    print(
        "Size Optional Header".ljust(25),
        f"{address+20:0>8x}-{address+22:0>8x}".ljust(20),
        hexlify(data).decode().ljust(40),
        "".join(chr(x) if x in printable else "." for x in data).ljust(20),
        "Optional headers size:",
        optional_headers_size,
    )
    data = file.read(2)
    data_int = int.from_bytes(data, "little")
    if data_int & 0b0000000000000001:
        print(
            "Characteristics".ljust(25),
            f"{address+22:0>8x}-{address+24:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            "Image only - No relocations",
        )
    if data_int & 0b0000000000000010:
        print(
            "Characteristics".ljust(25),
            f"{address+22:0>8x}-{address+24:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            "Image only - can be run",
        )
    if data_int & 0b0000000000000100:
        print(
            "Characteristics".ljust(25),
            f"{address+22:0>8x}-{address+24:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            "COFF line numbers is removed",
        )
    if data_int & 0b0000000000001000:
        print(
            "Characteristics".ljust(25),
            f"{address+22:0>8x}-{address+24:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            "COFF symbol table removed",
        )
    if data_int & 0b0000000000010000:
        print(
            "Characteristics".ljust(25),
            f"{address+22:0>8x}-{address+24:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            "Aggressively trim working set",
        )
    if data_int & 0b0000000000100000:
        print(
            "Characteristics".ljust(25),
            f"{address+22:0>8x}-{address+24:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            "Can handle > 2GB addresses",
        )
    if data_int & 0b0000000001000000:
        print(
            "Characteristics".ljust(25),
            f"{address+22:0>8x}-{address+24:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            "Reserved for future",
        )
    if data_int & 0b0000000010000000:
        print(
            "Characteristics".ljust(25),
            f"{address+22:0>8x}-{address+24:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            "Little endian",
        )
    if data_int & 0b0000000100000000:
        print(
            "Characteristics".ljust(25),
            f"{address+22:0>8x}-{address+24:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            "32 bit word architecture",
        )
    if data_int & 0b0000000100000000:
        print(
            "Characteristics".ljust(25),
            f"{address+22:0>8x}-{address+24:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            "No debug informations",
        )
    if data_int & 0b0000010000000000:
        print(
            "Characteristics".ljust(25),
            f"{address+22:0>8x}-{address+24:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            "Media Load and copy to swap",
        )
    if data_int & 0b0000100000000000:
        print(
            "Characteristics".ljust(25),
            f"{address+22:0>8x}-{address+24:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            "Network Load and copy to swap",
        )
    if data_int & 0b0001000000000000:
        print(
            "Characteristics".ljust(25),
            f"{address+22:0>8x}-{address+24:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            "System file, not user program",
        )
    if data_int & 0b0010000000000000:
        print(
            "Characteristics".ljust(25),
            f"{address+22:0>8x}-{address+24:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            "Is a DLL",
        )
    if data_int & 0b0100000000000000:
        print(
            "Characteristics".ljust(25),
            f"{address+22:0>8x}-{address+24:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            "Run only with uniprocessor",
        )
    if data_int & 0b1000000000000000:
        print(
            "Characteristics".ljust(25),
            f"{address+22:0>8x}-{address+24:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            "Big endian",
        )
    print("\n", f"{' Optional Headers ':*^139}", "", sep="\n")
    address += 24
    data = file.read(2)
    if data == b"\x0b\x01":
        information = "PE32 magic"
        exe_architecture = 32
    elif data == b"\x0b\x02":
        information = "PE32+ magic"
        exe_architecture = 64
    else:
        print(
            "",
            "PE32 magic (0x0b01) and PE32+ magic (0x0b02) not found !"
            " Is not a DOS native executable.",
            "",
            sep="",
            file=stderr,
        )
        exit(2)
    print(
        "Magic".ljust(25),
        f"{address:0>8x}-{address+2:0>8x}".ljust(20),
        hexlify(data).decode().ljust(40),
        "".join(chr(x) if x in printable else "." for x in data).ljust(20),
        information,
    )
    data = file.read(1)
    print(
        "MajorVersion".ljust(25),
        f"{address+2:0>8x}-{address+3:0>8x}".ljust(20),
        hexlify(data).decode().ljust(40),
        "".join(chr(x) if x in printable else "." for x in data).ljust(20),
        "Major linker version:",
        int.from_bytes(data, "little"),
    )
    data = file.read(1)
    print(
        "MinorVersion".ljust(25),
        f"{address+3:0>8x}-{address+4:0>8x}".ljust(20),
        hexlify(data).decode().ljust(40),
        "".join(chr(x) if x in printable else "." for x in data).ljust(20),
        "Minor linker version:",
        int.from_bytes(data, "little"),
    )
    data = file.read(4)
    print(
        "SizeOfCode".ljust(25),
        f"{address+4:0>8x}-{address+8:0>8x}".ljust(20),
        hexlify(data).decode().ljust(40),
        "".join(chr(x) if x in printable else "." for x in data).ljust(20),
        ".text section size:",
        int.from_bytes(data, "little"),
    )
    data = file.read(4)
    print(
        "SizeInitData".ljust(25),
        f"{address+8:0>8x}-{address+12:0>8x}".ljust(20),
        hexlify(data).decode().ljust(40),
        "".join(chr(x) if x in printable else "." for x in data).ljust(20),
        ".data section size:",
        int.from_bytes(data, "little"),
    )
    data = file.read(4)
    print(
        "SizeUnInitData".ljust(25),
        f"{address+12:0>8x}-{address+16:0>8x}".ljust(20),
        hexlify(data).decode().ljust(40),
        "".join(chr(x) if x in printable else "." for x in data).ljust(20),
        ".bss section size:",
        int.from_bytes(data, "little"),
    )
    data = file.read(4)
    entry_point = int.from_bytes(data, "little")
    print(
        "AddressEntryPoint".ljust(25),
        f"{address+16:0>8x}-{address+20:0>8x}".ljust(20),
        hexlify(data).decode().ljust(40),
        "".join(chr(x) if x in printable else "." for x in data).ljust(20),
        "_start position:",
        entry_point,
    )
    data = file.read(4)
    print(
        "BaseOfCode".ljust(25),
        f"{address+20:0>8x}-{address+24:0>8x}".ljust(20),
        hexlify(data).decode().ljust(40),
        "".join(chr(x) if x in printable else "." for x in data).ljust(20),
        ".text position:",
        int.from_bytes(data, "little"),
    )
    if exe_architecture == 32:
        data = file.read(4)
        print(
            "BaseOfData".ljust(25),
            f"{address+24:0>8x}-{address+28:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            ".data position:",
            int.from_bytes(data, "little"),
        )
    if exe_architecture == 32:
        start = 28
        data = file.read(4)
    else:
        start = 24
        data = file.read(8)
    if data[-4:] == b"\x01\x00\x00\x00":
        description = "EXE default position"
    elif data[-4:] == b"\x00\x01\x00\x00":
        description = "CE EXE default position"
    elif data[-4:] == b"\x00\x40\x00\x00":
        description = "DLL default position"
    else:
        description = f"Loaded position: ({int.from_bytes(data, 'little')})"
    print(
        "ImageBase".ljust(25),
        f"{address+start:0>8x}-{address+32:0>8x}".ljust(20),
        hexlify(data).decode().ljust(40),
        "".join(chr(x) if x in printable else "." for x in data).ljust(20),
        description,
    )
    data = file.read(4)
    print(
        "SectionAlignment".ljust(25),
        f"{address+32:0>8x}-{address+36:0>8x}".ljust(20),
        hexlify(data).decode().ljust(40),
        "".join(chr(x) if x in printable else "." for x in data).ljust(20),
        "Section alignment:",
        int.from_bytes(data, "little"),
    )
    data = file.read(4)
    print(
        "FileAlignment".ljust(25),
        f"{address+36:0>8x}-{address+40:0>8x}".ljust(20),
        hexlify(data).decode().ljust(40),
        "".join(chr(x) if x in printable else "." for x in data).ljust(20),
        "File alignment:",
        int.from_bytes(data, "little"),
    )
    data = file.read(2)
    print(
        "MajorOsVersion".ljust(25),
        f"{address+40:0>8x}-{address+42:0>8x}".ljust(20),
        hexlify(data).decode().ljust(40),
        "".join(chr(x) if x in printable else "." for x in data).ljust(20),
        "Major OS version:",
        int.from_bytes(data, "little"),
    )
    data = file.read(2)
    print(
        "MinorOsVersion".ljust(25),
        f"{address+42:0>8x}-{address+44:0>8x}".ljust(20),
        hexlify(data).decode().ljust(40),
        "".join(chr(x) if x in printable else "." for x in data).ljust(20),
        "Minor OS version:",
        int.from_bytes(data, "little"),
    )
    data = file.read(2)
    print(
        "MajorImageVersion".ljust(25),
        f"{address+44:0>8x}-{address+46:0>8x}".ljust(20),
        hexlify(data).decode().ljust(40),
        "".join(chr(x) if x in printable else "." for x in data).ljust(20),
        "Maj Image version:",
        int.from_bytes(data, "little"),
    )
    data = file.read(2)
    print(
        "MinorImageVersion".ljust(25),
        f"{address+46:0>8x}-{address+48:0>8x}".ljust(20),
        hexlify(data).decode().ljust(40),
        "".join(chr(x) if x in printable else "." for x in data).ljust(20),
        "Min Image version:",
        int.from_bytes(data, "little"),
    )
    data = file.read(2)
    print(
        "MajorSubsystemVersion".ljust(25),
        f"{address+48:0>8x}-{address+50:0>8x}".ljust(20),
        hexlify(data).decode().ljust(40),
        "".join(chr(x) if x in printable else "." for x in data).ljust(20),
        "Maj SubSystem version:",
        int.from_bytes(data, "little"),
    )
    data = file.read(2)
    print(
        "MinorSubsystemVersion".ljust(25),
        f"{address+50:0>8x}-{address+52:0>8x}".ljust(20),
        hexlify(data).decode().ljust(40),
        "".join(chr(x) if x in printable else "." for x in data).ljust(20),
        "Min SubSystem version:",
        int.from_bytes(data, "little"),
    )
    data = file.read(4)
    print(
        "Win32VersionValue".ljust(25),
        f"{address+52:0>8x}-{address+56:0>8x}".ljust(20),
        hexlify(data).decode().ljust(40),
        "".join(chr(x) if x in printable else "." for x in data).ljust(20),
        "Win32 version:",
        int.from_bytes(data, "little"),
    )
    data = file.read(4)
    print(
        "SizeOfImage".ljust(25),
        f"{address+56:0>8x}-{address+60:0>8x}".ljust(20),
        hexlify(data).decode().ljust(40),
        "".join(chr(x) if x in printable else "." for x in data).ljust(20),
        "Image (memory) size:",
        int.from_bytes(data, "little"),
    )
    data = file.read(4)
    print(
        "SizeOfHeaders".ljust(25),
        f"{address+60:0>8x}-{address+64:0>8x}".ljust(20),
        hexlify(data).decode().ljust(40),
        "".join(chr(x) if x in printable else "." for x in data).ljust(20),
        "Headers size:",
        int.from_bytes(data, "little"),
    )
    data = file.read(4)
    print(
        "CheckSum".ljust(25),
        f"{address+64:0>8x}-{address+68:0>8x}".ljust(20),
        hexlify(data).decode().ljust(40),
        "".join(chr(x) if x in printable else "." for x in data).ljust(20),
        "Checksum:",
        int.from_bytes(data, "little"),
    )
    data = file.read(2)
    if data == b"\x01\x00":
        description = "Doesn't require subsystem"
    elif data == b"\x02\x00":
        description = "Windows GUI subsystem"
    elif data == b"\x03\x00":
        description = "Windows console subsystem"
    elif data == b"\x04\x00":
        description = "Unknown"
    elif data == b"\x05\x00":
        description = "OS/2 console subsystem"
    elif data == b"\x06\x00":
        description = "Unknown"
    elif data == b"\x07\x00":
        description = "POSIX console subsystem"
    else:
        description = "Unknown"
    print(
        "Subsystem".ljust(25),
        f"{address+68:0>8x}-{address+70:0>8x}".ljust(20),
        hexlify(data).decode().ljust(40),
        "".join(chr(x) if x in printable else "." for x in data).ljust(20),
        description,
    )
    data = file.read(2)
    data_int = int.from_bytes(data, "little")
    if data_int & 0b0000000000000001:
        print(
            "DllCharacteristics".ljust(25),
            f"{address+70:0>8x}-{address+72:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            "Reserved",
        )
    if data_int & 0b0000000000000010:
        print(
            "DllCharacteristics".ljust(25),
            f"{address+70:0>8x}-{address+72:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            "Reserved",
        )
    if data_int & 0b0000000000000100:
        print(
            "DllCharacteristics".ljust(25),
            f"{address+70:0>8x}-{address+72:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            "Reserved",
        )
    if data_int & 0b0000000000001000:
        print(
            "DllCharacteristics".ljust(25),
            f"{address+70:0>8x}-{address+72:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            "Reserved",
        )
    if data_int & 0b0000000000010000:
        print(
            "DllCharacteristics".ljust(25),
            f"{address+70:0>8x}-{address+72:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            "Not documented",
        )
    if data_int & 0b0000000000100000:
        print(
            "DllCharacteristics".ljust(25),
            f"{address+70:0>8x}-{address+72:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            "64-bit virtual address space",
        )
    if data_int & 0b0000000001000000:
        print(
            "DllCharacteristics".ljust(25),
            f"{address+70:0>8x}-{address+72:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            "DLL can be relocated",
        )
    if data_int & 0b0000000010000000:
        print(
            "DllCharacteristics".ljust(25),
            f"{address+70:0>8x}-{address+72:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            "Code Integrity enforced",
        )
    if data_int & 0b0000000100000000:
        print(
            "DllCharacteristics".ljust(25),
            f"{address+70:0>8x}-{address+72:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            "NX compatible",
        )
    if data_int & 0b0000000100000000:
        print(
            "DllCharacteristics".ljust(25),
            f"{address+70:0>8x}-{address+72:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            "Isolation aware",
        )
    if data_int & 0b0000010000000000:
        print(
            "DllCharacteristics".ljust(25),
            f"{address+70:0>8x}-{address+72:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            "No structured exception",
        )
    if data_int & 0b0000100000000000:
        print(
            "DllCharacteristics".ljust(25),
            f"{address+70:0>8x}-{address+72:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            "Do not bind the image",
        )
    if data_int & 0b0001000000000000:
        print(
            "DllCharacteristics".ljust(25),
            f"{address+70:0>8x}-{address+72:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            "Execute in AppContainer",
        )
    if data_int & 0b0010000000000000:
        print(
            "DllCharacteristics".ljust(25),
            f"{address+70:0>8x}-{address+72:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            "WDM driver",
        )
    if data_int & 0b0100000000000000:
        print(
            "DllCharacteristics".ljust(25),
            f"{address+70:0>8x}-{address+72:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            "Control Flow Guard",
        )
    if data_int & 0b1000000000000000:
        print(
            "DllCharacteristics".ljust(25),
            f"{address+70:0>8x}-{address+72:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            "Terminal Server aware",
        )
    address += 72
    block_size = 4 if exe_architecture == 32 else 8
    data = file.read(block_size)
    print(
        "SizeOfStackReserve".ljust(25),
        f"{address:0>8x}-{address+block_size:0>8x}".ljust(20),
        hexlify(data).decode().ljust(40),
        "".join(chr(x) if x in printable else "." for x in data).ljust(20),
        int.from_bytes(data, "little"),
        "bytes reserved (stack)",
    )
    address += block_size
    data = file.read(block_size)
    print(
        "SizeOfStackCommit".ljust(25),
        f"{address:0>8x}-{address+block_size:0>8x}".ljust(20),
        hexlify(data).decode().ljust(40),
        "".join(chr(x) if x in printable else "." for x in data).ljust(20),
        "Stack commit size:",
        int.from_bytes(data, "little"),
    )
    address += block_size
    data = file.read(block_size)
    print(
        "SizeOfHeapReserve".ljust(25),
        f"{address:0>8x}-{address+block_size:0>8x}".ljust(20),
        hexlify(data).decode().ljust(40),
        "".join(chr(x) if x in printable else "." for x in data).ljust(20),
        int.from_bytes(data, "little"),
        "bytes reserved (heap)",
    )
    address += block_size
    data = file.read(block_size)
    address += block_size
    print(
        "SizeOfHeapCommit".ljust(25),
        f"{address:0>8x}-{address+block_size:0>8x}".ljust(20),
        hexlify(data).decode().ljust(40),
        "".join(chr(x) if x in printable else "." for x in data).ljust(20),
        "Heap commit size:",
        int.from_bytes(data, "little"),
    )
    data = file.read(4)
    vprint(
        "LoaderFlags".ljust(25),
        f"{address:0>8x}-{address+4:0>8x}".ljust(20),
        hexlify(data).decode().ljust(40),
        "".join(chr(x) if x in printable else "." for x in data).ljust(20),
    )
    data = file.read(4)
    vprint(
        "NumberOfRvaAndSizes".ljust(25),
        f"{address+4:0>8x}-{address+8:0>8x}".ljust(20),
        hexlify(data).decode().ljust(40),
        "".join(chr(x) if x in printable else "." for x in data).ljust(20),
    )
    print("\n", f"{' Data Directories ':*^139}", "\n", sep="")
    address += 8
    for i, label in enumerate(
        (
            "ExportSymbolsTable",
            "ImportSymbolsTable",
            "ResourceTable",
            "ExceptionTable",
            "CertificateTable",
            "BaseRelocationTable",
            "DebuggingInformation",
            "ArchitectureData",
            "GlobalPointerRegister",
            "ThreadStorageTable",
            "LoadConfigurationTable",
            "BoundImportTable",
            "ImportAddressTable",
            "DelayImportDescriptor",
            "CLR_Header",
            "Reserved",
        )
    ):
        rva = file.read(4)
        size = file.read(4)
        data = rva + size
        print(
            label.ljust(25),
            f"{address:0>8x}-{address+8:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            "Size:",
            int.from_bytes(size, "little"),
            "; RVA:",
            int.from_bytes(rva, "little"),
        )
        if i == 2:
            rva_resource = int.from_bytes(rva, "little")
            temp_position = file.tell()
            file.seek(rva_resource)
            data_position = int.from_bytes(file.read(4), "little")
            file.seek(temp_position)
        elif i == 0:
            rva_export = int.from_bytes(rva, "little")
            size_export = int.from_bytes(size, "little")
        elif i == 1:
            rva_import = int.from_bytes(rva, "little")
            size_import = int.from_bytes(size, "little")
        address += 8
    first_section_offset = pe_address + 24 + optional_headers_size
    if address != first_section_offset:
        data = file.read(first_section_offset - address)
        print(
            "",
            f"Move from position ({address}) to first "
            f"section position ({first_section_offset}) [{data}].",
            "",
            sep="",
            file=stderr,
        )
        address = first_section_offset
    print("\n", f"{' Sections ':*^139}", "\n", sep="")
    for i in range(section_number):
        name = file.read(8)
        label = (
            "Section " + name.replace(b"\0", b"").decode("latin-1")
        ).ljust(25)
        data = file.read(4)
        virtual_size = int.from_bytes(data, "little")
        print(
            label,
            f"{address+8:0>8x}-{address+12:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            "Physical address:",
            virtual_size,
        )
        vprint(
            label,
            f"{address+8:0>8x}-{address+12:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            "Virtual size:",
            virtual_size,
        )
        data = file.read(4)
        virtual_address = int.from_bytes(data, "little")
        print(
            label,
            f"{address+12:0>8x}-{address+16:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            "Virtual address:",
            virtual_address,
        )
        data = file.read(4)
        if virtual_address == rva_resource:
            data_size = int.from_bytes(data, "little")
            rsrc_virtual_address = virtual_address
        section_size = int.from_bytes(data, "little")
        print(
            label,
            f"{address+16:0>8x}-{address+20:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            "Size of data:",
            section_size,
        )
        data = file.read(4)
        if virtual_address == rva_resource:
            data_position = int.from_bytes(data, "little")
        if virtual_address <= rva_export and rva_export <= (
            virtual_address + virtual_size
        ):
            export_virtual_address = virtual_address
            export_data_position = int.from_bytes(data, "little")
        if virtual_address <= rva_import and rva_import <= (
            virtual_address + virtual_size
        ):
            import_virtual_address = virtual_address
            import_virtual_size = virtual_size
            import_data_position = int.from_bytes(data, "little")
        section_address = int.from_bytes(data, "little")
        print(
            label,
            f"{address+20:0>8x}-{address+24:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            "Data address:",
            int.from_bytes(data, "little"),
        )
        section = Section(label.split()[1], section_address, section_size)
        section.virtual_address = virtual_address
        section.virtual_size = virtual_size
        section.color = tuple(x / 255 for x in generate_color())
        sections.append(section)
        data = file.read(4)
        vprint(
            label,
            f"{address+24:0>8x}-{address+28:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            "Relocation address:",
            int.from_bytes(data, "little"),
        )
        data = file.read(4)
        vprint(
            label,
            f"{address+28:0>8x}-{address+32:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            "Line number address:",
            int.from_bytes(data, "little"),
        )
        data = file.read(2)
        vprint(
            label,
            f"{address+32:0>8x}-{address+34:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            "Relocations number:",
            int.from_bytes(data, "little"),
        )
        data = file.read(2)
        vprint(
            label,
            f"{address+34:0>8x}-{address+36:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            "Linenumber number:",
            int.from_bytes(data, "little"),
        )
        data = file.read(4)
        data_value = int.from_bytes(data, "little")
        vprint(
            label,
            f"{address+36:0>8x}-{address+40:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            "Characteristics value:",
            data_value,
        )
        if data_value & 0x00000008:
            print(
                label,
                f"{address+36:0>8x}-{address+40:0>8x}".ljust(20),
                hexlify(data).decode().ljust(40),
                "".join(chr(x) if x in printable else "." for x in data).ljust(
                    20
                ),
                "Not padded",
            )
        if data_value & 0x00000020:
            print(
                label,
                f"{address+36:0>8x}-{address+40:0>8x}".ljust(20),
                hexlify(data).decode().ljust(40),
                "".join(chr(x) if x in printable else "." for x in data).ljust(
                    20
                ),
                "Executable code",
            )
        if data_value & 0x00000040:
            print(
                label,
                f"{address+36:0>8x}-{address+40:0>8x}".ljust(20),
                hexlify(data).decode().ljust(40),
                "".join(chr(x) if x in printable else "." for x in data).ljust(
                    20
                ),
                "Initialized data",
            )
        if data_value & 0x00000080:
            print(
                label,
                f"{address+36:0>8x}-{address+40:0>8x}".ljust(20),
                hexlify(data).decode().ljust(40),
                "".join(chr(x) if x in printable else "." for x in data).ljust(
                    20
                ),
                "Uninitialized data",
            )
        if data_value & 0x00000200:
            print(
                label,
                f"{address+36:0>8x}-{address+40:0>8x}".ljust(20),
                hexlify(data).decode().ljust(40),
                "".join(chr(x) if x in printable else "." for x in data).ljust(
                    20
                ),
                "Comments && informations",
            )
        if data_value & 0x00000800:
            print(
                label,
                f"{address+36:0>8x}-{address+40:0>8x}".ljust(20),
                hexlify(data).decode().ljust(40),
                "".join(chr(x) if x in printable else "." for x in data).ljust(
                    20
                ),
                "Not a part of the image",
            )
        if data_value & 0x00001000:
            print(
                label,
                f"{address+36:0>8x}-{address+40:0>8x}".ljust(20),
                hexlify(data).decode().ljust(40),
                "".join(chr(x) if x in printable else "." for x in data).ljust(
                    20
                ),
                "COMDAT data",
            )
        if data_value & 0x00004000:
            print(
                label,
                f"{address+36:0>8x}-{address+40:0>8x}".ljust(20),
                hexlify(data).decode().ljust(40),
                "".join(chr(x) if x in printable else "." for x in data).ljust(
                    20
                ),
                "Reset exceptions in the TLB",
            )
        if data_value & 0x00008000:
            print(
                label,
                f"{address+36:0>8x}-{address+40:0>8x}".ljust(20),
                hexlify(data).decode().ljust(40),
                "".join(chr(x) if x in printable else "." for x in data).ljust(
                    20
                ),
                "Data using global pointer",
            )
        if data_value & 0x00100000:
            print(
                label,
                f"{address+36:0>8x}-{address+40:0>8x}".ljust(20),
                hexlify(data).decode().ljust(40),
                "".join(chr(x) if x in printable else "." for x in data).ljust(
                    20
                ),
                "Align 1-byte boundary",
            )
        if data_value & 0x00200000:
            print(
                label,
                f"{address+36:0>8x}-{address+40:0>8x}".ljust(20),
                hexlify(data).decode().ljust(40),
                "".join(chr(x) if x in printable else "." for x in data).ljust(
                    20
                ),
                "Align 2-byte boundary",
            )
        if data_value & 0x00300000:
            print(
                label,
                f"{address+36:0>8x}-{address+40:0>8x}".ljust(20),
                hexlify(data).decode().ljust(40),
                "".join(chr(x) if x in printable else "." for x in data).ljust(
                    20
                ),
                "Align 4-byte boundary",
            )
        if data_value & 0x00400000:
            print(
                label,
                f"{address+36:0>8x}-{address+40:0>8x}".ljust(20),
                hexlify(data).decode().ljust(40),
                "".join(chr(x) if x in printable else "." for x in data).ljust(
                    20
                ),
                "Align 8-byte boundary",
            )
        if data_value & 0x00500000:
            print(
                label,
                f"{address+36:0>8x}-{address+40:0>8x}".ljust(20),
                hexlify(data).decode().ljust(40),
                "".join(chr(x) if x in printable else "." for x in data).ljust(
                    20
                ),
                "Align 16-byte boundary",
            )
        if data_value & 0x00600000:
            print(
                label,
                f"{address+36:0>8x}-{address+40:0>8x}".ljust(20),
                hexlify(data).decode().ljust(40),
                "".join(chr(x) if x in printable else "." for x in data).ljust(
                    20
                ),
                "Align 32-byte boundary",
            )
        if data_value & 0x00700000:
            print(
                label,
                f"{address+36:0>8x}-{address+40:0>8x}".ljust(20),
                hexlify(data).decode().ljust(40),
                "".join(chr(x) if x in printable else "." for x in data).ljust(
                    20
                ),
                "Align 64-byte boundary",
            )
        if data_value & 0x00800000:
            print(
                label,
                f"{address+36:0>8x}-{address+40:0>8x}".ljust(20),
                hexlify(data).decode().ljust(40),
                "".join(chr(x) if x in printable else "." for x in data).ljust(
                    20
                ),
                "Align 128-byte boundary",
            )
        if data_value & 0x00900000:
            print(
                label,
                f"{address+36:0>8x}-{address+40:0>8x}".ljust(20),
                hexlify(data).decode().ljust(40),
                "".join(chr(x) if x in printable else "." for x in data).ljust(
                    20
                ),
                "Align 256-byte boundary",
            )
        if data_value & 0x00A00000:
            print(
                label,
                f"{address+36:0>8x}-{address+40:0>8x}".ljust(20),
                hexlify(data).decode().ljust(40),
                "".join(chr(x) if x in printable else "." for x in data).ljust(
                    20
                ),
                "Align 512-byte boundary",
            )
        if data_value & 0x00B00000:
            print(
                label,
                f"{address+36:0>8x}-{address+40:0>8x}".ljust(20),
                hexlify(data).decode().ljust(40),
                "".join(chr(x) if x in printable else "." for x in data).ljust(
                    20
                ),
                "Align 1024-byte boundary",
            )
        if data_value & 0x00C00000:
            print(
                label,
                f"{address+36:0>8x}-{address+40:0>8x}".ljust(20),
                hexlify(data).decode().ljust(40),
                "".join(chr(x) if x in printable else "." for x in data).ljust(
                    20
                ),
                "Align 2048-byte boundary",
            )
        if data_value & 0x00D00000:
            print(
                label,
                f"{address+36:0>8x}-{address+40:0>8x}".ljust(20),
                hexlify(data).decode().ljust(40),
                "".join(chr(x) if x in printable else "." for x in data).ljust(
                    20
                ),
                "Align 4096-byte boundary",
            )
        if data_value & 0x00E00000:
            print(
                label,
                f"{address+36:0>8x}-{address+40:0>8x}".ljust(20),
                hexlify(data).decode().ljust(40),
                "".join(chr(x) if x in printable else "." for x in data).ljust(
                    20
                ),
                "Align 8192-byte boundary",
            )
        if data_value & 0x01000000:
            print(
                label,
                f"{address+36:0>8x}-{address+40:0>8x}".ljust(20),
                hexlify(data).decode().ljust(40),
                "".join(chr(x) if x in printable else "." for x in data).ljust(
                    20
                ),
                "Extended relocations",
            )
        if data_value & 0x02000000:
            print(
                label,
                f"{address+36:0>8x}-{address+40:0>8x}".ljust(20),
                hexlify(data).decode().ljust(40),
                "".join(chr(x) if x in printable else "." for x in data).ljust(
                    20
                ),
                "Discarded as needed",
            )
        if data_value & 0x04000000:
            print(
                label,
                f"{address+36:0>8x}-{address+40:0>8x}".ljust(20),
                hexlify(data).decode().ljust(40),
                "".join(chr(x) if x in printable else "." for x in data).ljust(
                    20
                ),
                "Cannot be cached",
            )
        if data_value & 0x08000000:
            print(
                label,
                f"{address+36:0>8x}-{address+40:0>8x}".ljust(20),
                hexlify(data).decode().ljust(40),
                "".join(chr(x) if x in printable else "." for x in data).ljust(
                    20
                ),
                "Cannot be paged",
            )
        if data_value & 0x10000000:
            print(
                label,
                f"{address+36:0>8x}-{address+40:0>8x}".ljust(20),
                hexlify(data).decode().ljust(40),
                "".join(chr(x) if x in printable else "." for x in data).ljust(
                    20
                ),
                "Shared in memory",
            )
        if data_value & 0x20000000:
            print(
                label,
                f"{address+36:0>8x}-{address+40:0>8x}".ljust(20),
                hexlify(data).decode().ljust(40),
                "".join(chr(x) if x in printable else "." for x in data).ljust(
                    20
                ),
                "Executed as code",
            )
        if data_value & 0x40000000:
            print(
                label,
                f"{address+36:0>8x}-{address+40:0>8x}".ljust(20),
                hexlify(data).decode().ljust(40),
                "".join(chr(x) if x in printable else "." for x in data).ljust(
                    20
                ),
                "Read permissions",
            )
        if data_value & 0x80000000:
            print(
                label,
                f"{address+36:0>8x}-{address+40:0>8x}".ljust(20),
                hexlify(data).decode().ljust(40),
                "".join(chr(x) if x in printable else "." for x in data).ljust(
                    20
                ),
                "Write permissions",
            )
        if entry_point and virtual_address <= entry_point <= (
            virtual_address + virtual_size
        ):
            print(
                "Entry point section".ljust(25),
                f"{address+36:0>8x}-{address+40:0>8x}".ljust(20),
                hexlify(data).decode().ljust(40),
                "".join(chr(x) if x in printable else "." for x in data).ljust(
                    20
                ),
                label.split()[1],
            )
        address += 40
        # saved_position = file.tell()
        # file.seek(data_position)
        # data = file.read(data_size)
        # file.seek(saved_position)
    # saved_position = file.tell()
    position = data_position
    last_object = None
    entryend = 0
    file.seek(position)

    def read_base_entry():
        global position, last_object
        name = file.read(4)
        name_int = int.from_bytes(name, "little")
        offset = file.read(2)
        offset_int = int.from_bytes(offset, "little")
        type_ = file.read(2)
        type_int = int.from_bytes(type_, "little")
        data = name + offset + type_
        if name_int == 1:
            name = "Cursor"
        elif name_int == 2:
            name = "Bitmap"
        elif name_int == 3:
            name = "Icon"
        elif name_int == 4:
            name = "Menu"
        elif name_int == 5:
            name = "Dialog"
        elif name_int == 6:
            name = "String"
        elif name_int == 7:
            name = "FontDir"
        elif name_int == 8:
            name = "Font"
        elif name_int == 9:
            name = "Accelerator"
        elif name_int == 10:
            name = "RCData"
        elif name_int == 11:
            name = "MessageTable"
        elif name_int == 12:
            name = "Group Cursor"
        elif name_int == 14:
            name = "Group Icon"
        elif name_int == 16:
            last_object = name_int
            name = "Version"
        elif name_int == 17:
            name = "DLGInclude"
        elif name_int == 19:
            name = "PlugPlay"
        elif name_int == 20:
            name = "VXD"
        elif name_int == 21:
            name = "AniCursor"
        elif name_int == 22:
            name = "AniIcon"
        elif name_int == 23:
            name = "HTML"
        elif name_int == 24:
            last_object = name_int
            name = "Manifest"
        else:
            name = name.replace(b"\0", b"0")
        vprint(
            "Entry offset".ljust(25),
            f"{position:0>8x}-{position+8:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            offset_int,
        )
        vprint(
            "Entry type".ljust(25),
            f"{position:0>8x}-{position+8:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            type_int,
        )
        print(
            f"Entry {name}".ljust(25),
            f"{position:0>8x}-{position+8:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            name_int,
        )
        position += 8
        return type_int, offset_int

    def get_attribute(char=None):
        global position, entryend
        entryposition = position
        char = char or file.read(1)
        while char == b"\0":
            char = file.read(1)
            position += 1
        data_length = char + file.read(1)
        data_valuelength = file.read(2)
        data_type = file.read(2)
        length = int.from_bytes(data_length, "little")
        valuelength = int.from_bytes(data_valuelength, "little")
        type_ = int.from_bytes(data_type, "little")
        vprint(
            "String length".ljust(25),
            f"{position:0>8x}-{position+2:0>8x}".ljust(20),
            hexlify(data_length).decode().ljust(40),
            "".join(
                chr(x) if x in printable else "." for x in data_length
            ).ljust(20),
            length,
        )
        vprint(
            "String value length".ljust(25),
            f"{position+2:0>8x}-{position+4:0>8x}".ljust(20),
            hexlify(data_valuelength).decode().ljust(40),
            "".join(
                chr(x) if x in printable else "." for x in data_valuelength
            ).ljust(20),
            valuelength,
        )
        vprint(
            "String type".ljust(25),
            f"{position+4:0>8x}-{position+6:0>8x}".ljust(20),
            hexlify(data_type).decode().ljust(40),
            "".join(
                chr(x) if x in printable else "." for x in data_type
            ).ljust(20),
            type_,
        )
        position += 6
        string = b""
        start_string_position = position
        precedent_char = b"\0"
        char = file.read(1)
        position += 1
        while (
            char != b"\0" or precedent_char != b"\0"
        ) and position < entryend:
            string += char
            precedent_char = char
            char = file.read(1)
            position += 1
        string = string.replace(b"\0", b"")
        if len(string) <= 20:
            data = hexlify(string).decode().ljust(40)
        else:
            data = "\b"
        print(
            "Attribute name".ljust(25),
            f"{start_string_position:0>8x}-{position:0>8x}".ljust(20),
            data,
            "".join(chr(x) if x in printable else "." for x in string).ljust(
                20
            ),
        )
        char = file.read(1)
        position += 1
        while char == b"\0":
            char = file.read(1)
            position += 1
            start_string_position = position
        if valuelength > 1:
            precedent_char = char
            string = char
            char = file.read(1)
            position += 1
            while (
                char != b"\0" or precedent_char != b"\0"
            ) and position < entryend:
                string += char
                precedent_char = char
                char = file.read(1)
                position += 1
            string = string.replace(b"\0", b"")
            if len(string) <= 20:
                data = hexlify(string).decode().ljust(40)
            else:
                data = "\b"
            print(
                "Attribute value".ljust(25),
                f"{start_string_position:0>8x}-{position:0>8x}".ljust(20),
                data,
                "".join(
                    chr(x) if x in printable else "." for x in string
                ).ljust(20),
            )
            char = None
        if entryend > position + 10:
            get_attribute(char)
        else:
            file.seek(entryend)
            position = entryend

    def read_data_entry():
        global position, entryend
        offset = file.read(4)
        size = file.read(4)
        codepage = file.read(4)
        reserved = file.read(4)
        data = offset + size + codepage + reserved
        codepage = int.from_bytes(codepage, "little")
        offset = int.from_bytes(offset, "little")
        size = int.from_bytes(size, "little")
        vprint(
            "Entry Offset".ljust(25),
            f"{position:0>8x}-{position+16:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            offset,
        )
        print(
            "Entry Size".ljust(25),
            f"{position:0>8x}-{position+16:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            size,
        )
        vprint(
            "Entry CodePage".ljust(25),
            f"{position:0>8x}-{position+16:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            codepage,
        )
        if offset == 16:
            return read_data_entry()
        position = data_position + (offset - rsrc_virtual_address)
        if position <= 0:
            return size
        file.seek(position)
        if last_object == 24:
            string = b""
            start_string_position = position
            char = file.read(1)
            while char != b"\0":
                string += char
                char = file.read(1)
                position += 1
            print(
                "Manifest".ljust(25),
                f"{start_string_position:0>8x}-{position:0>8x}".ljust(20),
                "\b",
                "".join(
                    chr(x) for x in string if chr(x) in printable_
                ).strip(),
            )
        elif last_object == 16:
            end_position = size + position
            value_length = file.read(2)
            value_valuelength = file.read(2)
            value_type = file.read(2)
            length = int.from_bytes(value_length, "little")
            valuelength = int.from_bytes(value_valuelength, "little")
            type_ = int.from_bytes(value_type, "little")
            key = file.read(30).replace(b"\0", b"")
            print(
                "\n", f"{' Version start - In resources ':*^139}", "\n", sep=""
            )
            vprint(
                "Version length".ljust(25),
                f"{position:0>8x}-{position+2:0>8x}".ljust(20),
                hexlify(value_length).decode().ljust(40),
                "".join(
                    chr(x) if x in printable else "." for x in value_length
                ).ljust(20),
                length,
            )
            vprint(
                "Version value length".ljust(25),
                f"{position+2:0>8x}-{position+4:0>8x}".ljust(20),
                hexlify(value_valuelength).decode().ljust(40),
                "".join(
                    chr(x) if x in printable else "."
                    for x in value_valuelength
                ).ljust(20),
                valuelength,
            )
            vprint(
                "Version type".ljust(25),
                f"{position+4:0>8x}-{position+6:0>8x}".ljust(20),
                hexlify(value_type).decode().ljust(40),
                "".join(
                    chr(x) if x in printable else "." for x in value_type
                ).ljust(20),
                type_,
            )
            print(
                "Version key".ljust(25),
                f"{position+6:0>8x}-{position+36:0>8x}".ljust(20),
                hexlify(key).decode().ljust(40),
                "".join(chr(x) if x in printable else "." for x in key).ljust(
                    20
                ),
            )
            position += 36
            char = file.read(1)
            while char == b"\0":
                char = file.read(1)
                position += 1
            if not valuelength:
                return size
            signature = char + file.read(3)
            if signature == b"\xbd\x04\xef\xfe":
                part_decimal = file.read(2)
                part_integer = file.read(2)
                data = part_decimal + part_integer
                print(
                    "Structure version".ljust(25),
                    f"{position+4:0>8x}-{position+8:0>8x}".ljust(20),
                    hexlify(data).decode().ljust(40),
                    "".join(
                        chr(x) if x in printable else "." for x in data
                    ).ljust(20),
                    str(int.from_bytes(part_integer, "little"))
                    + "."
                    + str(int.from_bytes(part_decimal, "little")),
                )
                part_decimal = file.read(4)
                part_integer = file.read(4)
                data = part_decimal + part_integer
                print(
                    "File version".ljust(25),
                    f"{position+8:0>8x}-{position+16:0>8x}".ljust(20),
                    hexlify(data).decode().ljust(40),
                    "".join(
                        chr(x) if x in printable else "." for x in data
                    ).ljust(20),
                    str(int.from_bytes(part_integer, "little"))
                    + "."
                    + str(int.from_bytes(part_decimal, "little")),
                )
                part_decimal = file.read(4)
                part_integer = file.read(4)
                data = part_decimal + part_integer
                print(
                    "Product version".ljust(25),
                    f"{position+16:0>8x}-{position+24:0>8x}".ljust(20),
                    hexlify(data).decode().ljust(40),
                    "".join(
                        chr(x) if x in printable else "." for x in data
                    ).ljust(20),
                    str(int.from_bytes(part_integer, "little"))
                    + "."
                    + str(int.from_bytes(part_decimal, "little")),
                )
                file_masks = file.read(4)
                file_flags = file.read(4)
                data = file_masks + file_flags
                file_flags = int.from_bytes(file_flags, "little")
                file_masks = int.from_bytes(file_masks, "little")
                file_flags = file_flags & file_masks
                flags = "Flags: "
                if file_flags & 0x1:
                    flags += "DEBUG, "
                if file_flags & 0x2:
                    flags += "PRERELEASE, "
                if file_flags & 0x4:
                    flags += "PATCHED, "
                if file_flags & 0x8:
                    flags += "PRIVATEBUILD, "
                if file_flags & 0x10:
                    flags += "INFOINFERRED, "
                if file_flags & 0x20:
                    flags += "SPECIALBUILD, "
                print(
                    "Flags".ljust(25),
                    f"{position+24:0>8x}-{position+32:0>8x}".ljust(20),
                    hexlify(data).decode().ljust(40),
                    "".join(
                        chr(x) if x in printable else "." for x in data
                    ).ljust(20),
                    flags,
                )
                data = file.read(4)
                if data == b"\0\0\1\0":
                    os = "MS-DOS"
                elif data == b"\0\0\4\0":
                    os = "Windows NT"
                elif data == b"\1\0\0\0":
                    os = "16-bit Windows"
                elif data == b"\4\0\0\0":
                    os = "32-bit Windows"
                elif data == b"\0\0\2\0":
                    os = "16-bit OS/2"
                elif data == b"\0\0\3\0":
                    os = "32-bit OS/2"
                elif data == b"\2\0\0\0":
                    os = "16-bit Presentation Manager"
                elif data == b"\3\0\0\0":
                    os = "32-bit Presentation Manager"
                elif data == b"\0\0\0\0":
                    os = "Unknown"
                elif data == b"\1\0\1\0":
                    os = "MS-DOS 16-bit Windows"
                elif data == b"\4\0\1\0":
                    os = "MS-DOS 32-bit Windows"
                elif data == b"\4\0\4\0":
                    os = "NT 32-bit Windows"
                elif data == b"\2\0\2\0":
                    os = "16-bit OS/2 Presentation Manager"
                elif data == b"\3\0\3\0":
                    os = "32-bit OS/2 Presentation Manager"
                else:
                    os = "Unknown"
                print(
                    "Version OS".ljust(25),
                    f"{position+32:0>8x}-{position+36:0>8x}".ljust(20),
                    hexlify(data).decode().ljust(40),
                    "".join(
                        chr(x) if x in printable else "." for x in data
                    ).ljust(20),
                    "Designed for:",
                    os,
                )
                data = file.read(4)
                if data == b"\1\0\0\0":
                    filetype = "Application"
                elif data == b"\2\0\0\0":
                    filetype = "DLL"
                elif data == b"\3\0\0\0":
                    filetype = "Driver"
                elif data == b"\4\0\0\0":
                    filetype = "Font"
                elif data == b"\7\0\0\0":
                    filetype = "Static-Link Library"
                elif data == b"\0\0\0\0":
                    filetype = "Unknown"
                elif data == b"\5\0\0\0":
                    filetype = "Virtual Device"
                else:
                    filetype = "Invalid"
                print(
                    "File type".ljust(25),
                    f"{position+36:0>8x}-{position+40:0>8x}".ljust(20),
                    hexlify(data).decode().ljust(40),
                    "".join(
                        chr(x) if x in printable else "." for x in data
                    ).ljust(20),
                    "File type:",
                    filetype,
                )
                precedent_data = data
                data = file.read(4)
                if precedent_data == b"\3\0\0\0":
                    if data == b"\x0a\0\0\0":
                        subfiletype = "Communication driver"
                    elif data == b"\4\0\0\0":
                        subfiletype = "Display driver"
                    elif data == b"\x08\0\0\0":
                        subfiletype = "Installable driver"
                    elif data == b"\2\0\0\0":
                        subfiletype = "Keyboard driver"
                    elif data == b"\3\0\0\0":
                        subfiletype = "Language driver"
                    elif data == b"\5\0\0\0":
                        subfiletype = "Mouse driver"
                    elif data == b"\6\0\0\0":
                        subfiletype = "Network driver"
                    elif data == b"\1\0\0\0":
                        subfiletype = "Printer driver"
                    elif data == b"\x09\0\0\0":
                        subfiletype = "Sound driver"
                    elif data == b"\7\0\0\0":
                        subfiletype = "System driver"
                    elif data == b"\x0c\0\0\0":
                        subfiletype = "Versioned printer driver"
                    elif data == b"\0\0\0\0":
                        subfiletype = "Unknown driver"
                    else:
                        subfiletype = "Invalid driver type"
                    print(
                        "Driver type".ljust(25),
                        f"{position+40:0>8x}-{position+44:0>8x}".ljust(20),
                        hexlify(data).decode().ljust(40),
                        "".join(
                            chr(x) if x in printable else "." for x in data
                        ).ljust(20),
                        subfiletype,
                    )
                elif precedent_data == b"\4\0\0\0":
                    if data == b"\1\0\0\0":
                        subfiletype = "Raster font"
                    elif data == b"\3\0\0\0":
                        subfiletype = "TrueType font"
                    elif data == b"\2\0\0\0":
                        subfiletype = "Vector font"
                    elif data == b"\0\0\0\0":
                        subfiletype = "Unknown font"
                    else:
                        subfiletype = "Invalid font type"
                    print(
                        "Font type".ljust(25),
                        f"{position+40:0>8x}-{position+44:0>8x}".ljust(20),
                        hexlify(data).decode().ljust(40),
                        "".join(
                            chr(x) if x in printable else "." for x in data
                        ).ljust(20),
                        subfiletype,
                    )
                most = file.read(4)
                least = file.read(4)
                data = most + least
                most = int.from_bytes(most, "little")
                least = int.from_bytes(least, "little")
                datetime_64 = (most << (32)) + least
                datetime = (datetime_64 >> 32) + (
                    datetime_64 & 0xFFFFFFFF
                ) / pow(2, 32)
                # datetime = (datetime_64 / 1e7) - 11644473600
                print(
                    "Creation datetime".ljust(25),
                    f"{position+44:0>8x}-{position+52:0>8x}".ljust(20),
                    hexlify(data).decode().ljust(40),
                    "".join(
                        chr(x) if x in printable else "." for x in data
                    ).ljust(20),
                    ctime(datetime),
                )
                position += 52
            else:
                print(
                    "Signature:".ljust(25),
                    f"{position:0>8x}-{position+4:0>8x}".ljust(20),
                    hexlify(signature).decode().ljust(40),
                    "".join(
                        chr(x) if x in printable else "." for x in signature
                    ).ljust(20),
                    "Invalid, must be:",
                    b"\xbd\x04\xef\xfe".hex(),
                    file=stderr,
                )
                position += 4
            char = file.read(1)
            while char == b"\0":
                char = file.read(1)
                position += 1
            data_length = char + file.read(1)
            data_valuelength = file.read(2)
            data_type = file.read(2)
            length = int.from_bytes(data_length, "little")
            valuelength = int.from_bytes(data_valuelength, "little")
            type_ = int.from_bytes(data_type, "little")
            vprint(
                "Version length".ljust(25),
                f"{position:0>8x}-{position+2:0>8x}".ljust(20),
                hexlify(data_length).decode().ljust(40),
                "".join(
                    chr(x) if x in printable else "." for x in data_length
                ).ljust(20),
                length,
            )
            vprint(
                "Version value length".ljust(25),
                f"{position+2:0>8x}-{position+4:0>8x}".ljust(20),
                hexlify(data_valuelength).decode().ljust(40),
                "".join(
                    chr(x) if x in printable else "." for x in data_valuelength
                ).ljust(20),
                valuelength,
            )
            vprint(
                "Version type".ljust(25),
                f"{position+4:0>8x}-{position+6:0>8x}".ljust(20),
                hexlify(data_type).decode().ljust(40),
                "".join(
                    chr(x) if x in printable else "." for x in data_type
                ).ljust(20),
                type_,
            )
            position += 6
            string = b""
            start_string_position = position
            precedent_char = b"\0"
            char = file.read(1)
            position += 1
            while char != b"\0" or precedent_char != b"\0":
                string += char
                precedent_char = char
                char = file.read(1)
                position += 1
            string = string.replace(b"\0", b"")
            if len(string) <= 20:
                data = hexlify(string).decode().ljust(40)
            else:
                data = "\b"
            print(
                "Version child key".ljust(25),
                f"{start_string_position:0>8x}-{position:0>8x}".ljust(20),
                data,
                "".join(
                    chr(x) if x in printable else "." for x in string
                ).ljust(20),
            )

            def read_VarFileInfo():
                global position
                char = file.read(1)
                while char == "\0":
                    position += 1
                    char = file.read(1)
                data_length = char + file.read(1)
                data_valuelength = file.read(2)
                data_type = file.read(2)
                length = int.from_bytes(data_length, "little")
                valuelength = int.from_bytes(data_valuelength, "little")
                type_ = int.from_bytes(data_type, "little")
                vprint(
                    "String length".ljust(25),
                    f"{position:0>8x}-{position+2:0>8x}".ljust(20),
                    hexlify(data_length).decode().ljust(40),
                    "".join(
                        chr(x) if x in printable else "." for x in data_length
                    ).ljust(20),
                    length,
                )
                vprint(
                    "String value length".ljust(25),
                    f"{position+2:0>8x}-{position+4:0>8x}".ljust(20),
                    hexlify(data_valuelength).decode().ljust(40),
                    "".join(
                        chr(x) if x in printable else "."
                        for x in data_valuelength
                    ).ljust(20),
                    valuelength,
                )
                vprint(
                    "String type".ljust(25),
                    f"{position+4:0>8x}-{position+6:0>8x}".ljust(20),
                    hexlify(data_type).decode().ljust(40),
                    "".join(
                        chr(x) if x in printable else "." for x in data_type
                    ).ljust(20),
                    type_,
                )
                position += 6
                char = file.read(1)
                position += 1
                while char == b"\0":
                    char = file.read(1)
                    position += 1
                    start_string_position = position
                precedent_char = char
                string = char
                char = file.read(1)
                position += 1
                while char != b"\0" or precedent_char != b"\0":
                    string += char
                    precedent_char = char
                    char = file.read(1)
                    position += 1
                string = string.replace(b"\0", b"")
                if len(string) <= 20:
                    data = hexlify(string).decode().ljust(40)
                else:
                    data = "\b"
                print(
                    "Attribute name".ljust(25),
                    f"{start_string_position:0>8x}-{position:0>8x}".ljust(20),
                    data,
                    "".join(
                        chr(x) if x in printable else "." for x in string
                    ).ljust(20),
                )
                char = file.read(3)
                position += 3
                # while char == b"\0":
                #     char = file.read(1)
                #     position += 1
                language = file.read(2)
                charset = file.read(2)
                data = language + charset
                languages = {
                    0x0401: "Arabic",
                    0x0415: "Polish",
                    0x0402: "Bulgarian",
                    0x0416: "Portuguese (Brazil)",
                    0x0403: "Catalan",
                    0x0417: "Rhaeto-Romanic",
                    0x0404: "Traditional Chinese",
                    0x0418: "Romanian",
                    0x0405: "Czech",
                    0x0419: "Russian",
                    0x0406: "Danish",
                    0x041A: "Croato-Serbian (Latin)",
                    0x0407: "German",
                    0x041B: "Slovak",
                    0x0408: "Greek",
                    0x041C: "Albanian",
                    0x0409: "U.S. English",
                    0x041D: "Swedish",
                    0x040A: "Castilian Spanish",
                    0x041E: "Thai",
                    0x040B: "Finnish",
                    0x041F: "Turkish",
                    0x040C: "French",
                    0x0420: "Urdu",
                    0x040D: "Hebrew",
                    0x0421: "Bahasa",
                    0x040E: "Hungarian",
                    0x0804: "Simplified Chinese",
                    0x040F: "Icelandic",
                    0x0807: "Swiss German",
                    0x0410: "Italian",
                    0x0809: "U.K. English",
                    0x0411: "Japanese",
                    0x080A: "Spanish (Mexico)",
                    0x0412: "Korean",
                    0x080C: "Belgian French",
                    0x0413: "Dutch",
                    0x0C0C: "Canadian French",
                    0x0414: "Norwegian – Bokmal",
                    0x100C: "Swiss French",
                    0x0810: "Swiss Italian",
                    0x0816: "Portuguese (Portugal)",
                    0x0813: "Belgian Dutch",
                    0x081A: "Serbo-Croatian (Cyrillic)",
                    0x0814: "Norwegian – Nynorsk",
                }
                language = languages.get(
                    int.from_bytes(language, "little"), "Unknown language"
                )
                charset = int.from_bytes(charset, "little")
                if charset == 0:
                    charset = "7-bit ASCII"
                elif charset == 932:
                    charset = "Japan (Shift – JIS X-0208)"
                elif charset == 949:
                    charset = "Korea (Shift – KSC 5601)"
                elif charset == 950:
                    charset = "Taiwan (Big5)"
                elif charset == 1200:
                    charset = "Unicode"
                elif charset == 1250:
                    charset = "Latin-2 (Eastern European)"
                elif charset == 1251:
                    charset = "Cyrillic"
                elif charset == 1252:
                    charset = "Multilingual"
                elif charset == 1253:
                    charset = "Greek"
                elif charset == 1254:
                    charset = "Turkish"
                elif charset == 1255:
                    charset = "Hebrew"
                elif charset == 1256:
                    charset = "Unknown charset"
                print(
                    "Attribute value".ljust(25),
                    f"{position:0>8x}-{position+4:0>8x}".ljust(20),
                    hexlify(data).decode().ljust(40),
                    "".join(
                        chr(x) if x in printable else "." for x in data
                    ).ljust(20),
                    language,
                    ";",
                    charset,
                )

            def read_StringFileInfo():
                global position, entryend
                char = file.read(1)
                while char == b"\0":
                    char = file.read(1)
                    position += 1
                data_length = char + file.read(1)
                data_valuelength = file.read(2)
                data_type = file.read(2)
                entrylength = length = int.from_bytes(data_length, "little")
                valuelength = int.from_bytes(data_valuelength, "little")
                type_ = int.from_bytes(data_type, "little")
                vprint(
                    "String length".ljust(25),
                    f"{position:0>8x}-{position+2:0>8x}".ljust(20),
                    hexlify(data_length).decode().ljust(40),
                    "".join(
                        chr(x) if x in printable else "." for x in data_length
                    ).ljust(20),
                    length,
                )
                vprint(
                    "String value length".ljust(25),
                    f"{position+2:0>8x}-{position+4:0>8x}".ljust(20),
                    hexlify(data_valuelength).decode().ljust(40),
                    "".join(
                        chr(x) if x in printable else "."
                        for x in data_valuelength
                    ).ljust(20),
                    valuelength,
                )
                vprint(
                    "String type".ljust(25),
                    f"{position+4:0>8x}-{position+6:0>8x}".ljust(20),
                    hexlify(data_type).decode().ljust(40),
                    "".join(
                        chr(x) if x in printable else "." for x in data_type
                    ).ljust(20),
                    type_,
                )
                data = file.read(8)
                language = data.replace(b"\0", b"").decode()
                languages = {
                    "000B": "fi",
                    "000C": "fr",
                    "000D": "he",
                    "000E": "hu",
                    "000F": "is",
                    "0010": "it",
                    "0011": "ja",
                    "0012": "ko",
                    "0013": "nl",
                    "0014": "no",
                    "0015": "pl",
                    "0016": "pt",
                    "0017": "rm",
                    "0018": "ro",
                    "0019": "ru",
                    "001A": "hr",
                    "001B": "sk",
                    "001C": "sq",
                    "001D": "sv",
                    "001E": "th",
                    "001F": "tr",
                    "0020": "ur",
                    "0021": "id",
                    "0022": "uk",
                    "0023": "be",
                    "0024": "sl",
                    "0025": "et",
                    "0026": "lv",
                    "0027": "lt",
                    "0028": "tg",
                    "0029": "fa",
                    "002A": "vi",
                    "002B": "hy",
                    "002C": "az",
                    "002D": "eu",
                    "002E": "hsb",
                    "002F": "mk",
                    "0030": "st",
                    "0031": "ts",
                    "0032": "tn",
                    "0033": "ve",
                    "0034": "xh",
                    "0035": "zu",
                    "0036": "af",
                    "0037": "ka",
                    "0038": "fo",
                    "0039": "hi",
                    "003A": "mt",
                    "003B": "se",
                    "003C": "ga",
                    "003D": "yi, reserved",
                    "003E": "ms",
                    "003F": "kk",
                    "0040": "ky",
                    "0041": "sw",
                    "0042": "tk",
                    "0043": "uz",
                    "0044": "tt",
                    "0045": "bn",
                    "0046": "pa",
                    "0047": "gu",
                    "0048": "or",
                    "0049": "ta",
                    "004A": "te",
                    "004B": "kn",
                    "004C": "ml",
                    "004D": "as",
                    "004E": "mr",
                    "004F": "sa",
                    "0050": "mn",
                    "0051": "bo",
                    "0052": "cy",
                    "0053": "km",
                    "0054": "lo",
                    "0055": "my",
                    "0056": "gl",
                    "0057": "kok",
                    "0058": "mni, reserved",
                    "0059": "sd",
                    "005A": "syr",
                    "005B": "si",
                    "005C": "chr",
                    "005D": "iu",
                    "005E": "am",
                    "005F": "tzm",
                    "0060": "ks",
                    "0061": "ne",
                    "0062": "fy",
                    "0063": "ps",
                    "0064": "fil",
                    "0065": "dv",
                    "0066": "bin, reserved",
                    "0067": "ff",
                    "0068": "ha",
                    "0069": "ibb, reserved",
                    "006A": "yo",
                    "006B": "quz",
                    "006C": "nso",
                    "006D": "ba",
                    "006E": "lb",
                    "006F": "kl",
                    "0070": "ig",
                    "0071": "kr, reserved",
                    "0072": "om",
                    "0073": "ti",
                    "0074": "gn",
                    "0075": "haw",
                    "0076": "la, reserved",
                    "0077": "so, reserved",
                    "0078": "ii",
                    "0079": "pap, reserved",
                    "007A": "arn",
                    "007B": "Neither defined nor reserved",
                    "007C": "moh",
                    "007D": "Neither defined nor reserved",
                    "007E": "br",
                    "007F": "Reserved for invariant locale behavior",
                    "0080": "ug",
                    "0081": "mi",
                    "0082": "oc",
                    "0083": "co",
                    "0084": "gsw",
                    "0085": "sah",
                    "0086": "qut",
                    "0087": "rw",
                    "0088": "wo",
                    "0089": "Neither defined nor reserved",
                    "008A": "Neither defined nor reserved",
                    "008B": "Neither defined nor reserved",
                    "008C": "prs",
                    "008D": "Neither defined nor reserved",
                    "008E": "Neither defined nor reserved",
                    "008F": "Neither defined nor reserved",
                    "0090": "Neither defined nor reserved",
                    "0091": "gd",
                    "0092": "ku",
                    "0093": "quc, reserved",
                    "0401": "ar-SA",
                    "0402": "bg-BG",
                    "0403": "ca-ES",
                    "0404": "zh-TW",
                    "0405": "cs-CZ",
                    "0406": "da-DK",
                    "0407": "de-DE",
                    "0408": "el-GR",
                    "0409": "en-US",
                    "040A": "es-ES_tradnl",
                    "040B": "fi-FI",
                    "040C": "fr-FR",
                    "040D": "he-IL",
                    "040E": "hu-HU",
                    "040F": "is-IS",
                    "0410": "it-IT",
                    "0411": "ja-JP",
                    "0412": "ko-KR",
                    "0413": "nl-NL",
                    "0414": "nb-NO",
                    "0415": "pl-PL",
                    "0416": "pt-BR",
                    "0417": "rm-CH",
                    "0418": "ro-RO",
                    "0419": "ru-RU",
                    "041A": "hr-HR",
                    "041B": "sk-SK",
                    "041C": "sq-AL",
                    "041D": "sv-SE",
                    "041E": "th-TH",
                    "041F": "tr-TR",
                    "0420": "ur-PK",
                    "0421": "id-ID",
                    "0422": "uk-UA",
                    "0423": "be-BY",
                    "0424": "sl-SI",
                    "0425": "et-EE",
                    "0426": "lv-LV",
                    "0427": "lt-LT",
                    "0428": "tg-Cyrl-TJ",
                    "0429": "fa-IR",
                    "042A": "vi-VN",
                    "042B": "hy-AM",
                    "042C": "az-Latn-AZ",
                    "042D": "eu-ES",
                    "042E": "hsb-DE",
                    "042F": "mk-MK",
                    "0430": "st-ZA",
                    "0431": "ts-ZA",
                    "0432": "tn-ZA",
                    "0433": "ve-ZA",
                    "0434": "xh-ZA",
                    "0435": "zu-ZA",
                    "0436": "af-ZA",
                    "0437": "ka-GE",
                    "0438": "fo-FO",
                    "0439": "hi-IN",
                    "043A": "mt-MT",
                    "043B": "se-NO",
                    "043D": "yi-001",
                    "043E": "ms-MY",
                    "043F": "kk-KZ",
                    "0440": "ky-KG",
                    "0441": "sw-KE",
                    "0442": "tk-TM",
                    "0443": "uz-Latn-UZ",
                    "0444": "tt-RU",
                    "0445": "bn-IN",
                    "0446": "pa-IN",
                    "0447": "gu-IN",
                    "0448": "or-IN",
                    "0449": "ta-IN",
                    "044A": "te-IN",
                    "044B": "kn-IN",
                    "044C": "ml-IN",
                    "044D": "as-IN",
                    "044E": "mr-IN",
                    "044F": "sa-IN",
                    "0450": "mn-MN",
                    "0451": "bo-CN",
                    "0452": "cy-GB",
                    "0453": "km-KH",
                    "0454": "lo-LA",
                    "0455": "my-MM",
                    "0456": "gl-ES",
                    "0457": "kok-IN",
                    "0458": "mni-IN, reserved",
                    "0459": "sd-Deva-IN, reserved",
                    "045A": "syr-SY",
                    "045B": "si-LK",
                    "045C": "chr-Cher-US",
                    "045D": "iu-Cans-CA",
                    "045E": "am-ET",
                    "045F": "tzm-Arab-MA",
                    "0460": "ks-Arab",
                    "0461": "ne-NP",
                    "0462": "fy-NL",
                    "0463": "ps-AF",
                    "0464": "fil-PH",
                    "0465": "dv-MV",
                    "0466": "bin-NG, reserved",
                    "0467": "ff-NG, ff-Latn-NG",
                    "0468": "ha-Latn-NG",
                    "0469": "ibb-NG, reserved",
                    "046A": "yo-NG",
                    "046B": "quz-BO",
                    "046C": "nso-ZA",
                    "046D": "ba-RU",
                    "046E": "lb-LU",
                    "046F": "kl-GL",
                    "0470": "ig-NG",
                    "0471": "kr-Latn-NG",
                    "0472": "om-ET",
                    "0473": "ti-ET",
                    "0474": "gn-PY",
                    "0475": "haw-US",
                    "0476": "la-VA",
                    "0477": "so-SO",
                    "0478": "ii-CN",
                    "0479": "pap-029, reserved",
                    "047A": "arn-CL",
                    "047C": "moh-CA",
                    "047E": "br-FR",
                    "0480": "ug-CN",
                    "0481": "mi-NZ",
                    "0482": "oc-FR",
                    "0483": "co-FR",
                    "0484": "gsw-FR",
                    "0485": "sah-RU",
                    "0486": "qut-GT, reserved",
                    "0487": "rw-RW",
                    "0488": "wo-SN",
                    "048C": "prs-AF",
                    "048D": "plt-MG, reserved",
                    "048E": "zh-yue-HK, reserved",
                    "048F": "tdd-Tale-CN, reserved",
                    "0490": "khb-Talu-CN, reserved",
                    "0491": "gd-GB",
                    "0492": "ku-Arab-IQ",
                    "0493": "quc-CO, reserved",
                    "0501": "qps-ploc",
                    "05FE": "qps-ploca",
                    "0801": "ar-IQ",
                    "0803": "ca-ES-valencia",
                    "0804": "zh-CN",
                    "0807": "de-CH",
                    "0809": "en-GB",
                    "080A": "es-MX",
                    "080C": "fr-BE",
                    "0810": "it-CH",
                    "0811": "ja-Ploc-JP, reserved",
                    "0813": "nl-BE",
                    "0814": "nn-NO",
                    "0816": "pt-PT",
                    "0818": "ro-MD",
                    "0819": "ru-MD",
                    "081A": "sr-Latn-CS",
                    "081D": "sv-FI",
                    "0820": "ur-IN",
                    "0827": "Neither defined nor reserved",
                    "082C": "az-Cyrl-AZ, reserved",
                    "082E": "dsb-DE",
                    "0832": "tn-BW",
                    "083B": "se-SE",
                    "083C": "ga-IE",
                    "083E": "ms-BN",
                    "083F": "kk-Latn-KZ, reserved",
                    "0843": "uz-Cyrl-UZ, reserved",
                    "0845": "bn-BD",
                    "0846": "pa-Arab-PK",
                    "0849": "ta-LK",
                    "0850": "mn-Mong-CN, reserved",
                    "0851": "bo-BT, reserved",
                    "0859": "sd-Arab-PK",
                    "085D": "iu-Latn-CA",
                    "085F": "tzm-Latn-DZ",
                    "0860": "ks-Deva-IN",
                    "0861": "ne-IN",
                    "0867": "ff-Latn-SN",
                    "086B": "quz-EC",
                    "0873": "ti-ER",
                    "09FF": "qps-plocm",
                    "0C00": "Locale without assigned LCID if the current user default locale. See section 2.2.1.",
                    "0C01": "ar-EG",
                    "0C04": "zh-HK",
                    "0C07": "de-AT",
                    "0C09": "en-AU",
                    "0C0A": "es-ES",
                    "0C0C": "fr-CA",
                    "0C1A": "sr-Cyrl-CS",
                    "0C3B": "se-FI",
                    "0C50": "mn-Mong-MN",
                    "0C51": "dz-BT",
                    "0C5F": "tmz-MA, reserved",
                    "0C6b": "quz-PE",
                    "1000": "Locale without assigned LCID if the current user default locale. See section 2.2.1.",
                    "1001": "ar-LY",
                    "1004": "zh-SG",
                    "1007": "de-LU",
                    "1009": "en-CA",
                    "100A": "es-GT",
                    "100C": "fr-CH",
                    "101A": "hr-BA",
                    "103B": "smj-NO",
                    "105F": "tzm-Tfng-MA",
                    "1401": "ar-DZ",
                    "1404": "zh-MO",
                    "1407": "de-LI",
                    "1409": "en-NZ",
                    "140A": "es-CR",
                    "140C": "fr-LU",
                    "141A": "bs-Latn-BA",
                    "143B": "smj-SE",
                    "1801": "ar-MA",
                    "1809": "en-IE",
                    "180A": "es-PA",
                    "180C": "fr-MC",
                    "181A": "sr-Latn-BA",
                    "183B": "sma-NO",
                    "1C01": "ar-TN",
                    "1C09": "en-ZA",
                    "1C0A": "es-DO",
                    "1C0C": "fr-029",
                    "1C1A": "sr-Cyrl-BA",
                    "1C3B": "sma-SE",
                    "2001": "ar-OM",
                    "2008": "Neither defined nor reserved",
                    "2009": "en-JM",
                    "200A": "es-VE",
                    "200C": "fr-RE",
                    "201A": "bs-Cyrl-BA",
                    "203B": "sms-FI",
                    "2401": "ar-YE",
                    "2409": "en-029, reserved",
                    "240A": "es-CO",
                    "240C": "fr-CD",
                    "241A": "sr-Latn-RS",
                    "243B": "smn-FI",
                    "2801": "ar-SY",
                    "2809": "en-BZ",
                    "280A": "es-PE",
                    "280C": "fr-SN",
                    "281A": "sr-Cyrl-RS",
                    "2C01": "ar-JO",
                    "2C09": "en-TT",
                    "2C0A": "es-AR",
                    "2C0C": "fr-CM",
                    "2C1A": "sr-Latn-ME",
                    "3000": (
                        "Unassigned LCID locale temporarily assigned"
                        " to LCID 0x3000. See section 2.2.1."
                    ),
                    "3001": "ar-LB",
                    "3009": "en-ZW",
                    "300A": "es-EC",
                    "300C": "fr-CI",
                    "301A": "sr-Cyrl-ME",
                    "3400": (
                        "Unassigned LCID locale temporarily "
                        "assigned to LCID 0x3400. See section 2.2.1."
                    ),
                    "3401": "ar-KW",
                    "3409": "en-PH",
                    "340A": "es-CL",
                    "340C": "fr-ML",
                    "3800": (
                        "Unassigned LCID locale temporarily "
                        "assigned to LCID 0x3800. See section 2.2.1."
                    ),
                    "3801": "ar-AE",
                    "3809": "en-ID, reserved",
                    "380A": "es-UY",
                    "380C": "fr-MA",
                    "3C00": (
                        "Unassigned LCID locale temporarily assigned"
                        " to LCID 0x3C00. See section 2.2.1."
                    ),
                    "3C01": "ar-BH",
                    "3C09": "en-HK",
                    "3C0A": "es-PY",
                    "3C0C": "fr-HT",
                    "4000": (
                        "Unassigned LCID locale temporarily "
                        "assigned to LCID 0x4000. See section 2.2.1."
                    ),
                    "4001": "ar-QA",
                    "4009": "en-IN",
                    "400A": "es-BO",
                    "4400": (
                        "Unassigned LCID locale temporarily "
                        "assigned to LCID 0x4400. See section 2.2.1."
                    ),
                    "4401": "ar-Ploc-SA, reserved",
                    "4409": "en-MY",
                    "440A": "es-SV",
                    "4800": (
                        "Unassigned LCID locale temporarily assigned"
                        " to LCID 0x4800. See section 2.2.1."
                    ),
                    "4801": "ar-145, reserved",
                    "4809": "en-SG",
                    "480A": "es-HN",
                    "4C00": (
                        "Unassigned LCID locale temporarily"
                        " assigned to LCID 0x4C00. See section 2.2.1."
                    ),
                    "4C09": "en-AE",
                    "4C0A": "es-NI",
                    "5009": "en-BH, reserved",
                    "500A": "es-PR",
                    "5409": "en-EG, reserved",
                    "540A": "es-US",
                    "5809": "en-JO, reserved",
                    "580A": "es-419, reserved",
                    "5C09": "en-KW, reserved",
                    "5C0A": "es-CU",
                    "6009": "en-TR, reserved",
                    "6409": "en-YE, reserved",
                    "641A": "bs-Cyrl",
                    "681A": "bs-Latn",
                    "6C1A": "sr-Cyrl",
                    "701A": "sr-Latn",
                    "703B": "smn",
                    "742C": "az-Cyrl",
                    "743B": "sms",
                    "7804": "zh",
                    "7814": "nn",
                    "781A": "bs",
                    "782C": "az-Latn",
                    "783B": "sma",
                    "783F": "kk-Cyrl, reserved",
                    "7843": "uz-Cyrl",
                    "7850": "mn-Cyrl",
                    "785D": "iu-Cans",
                    "785F": "tzm-Tfng",
                    "7C04": "zh-Hant",
                    "7C14": "nb",
                    "7C1A": "sr",
                    "7C28": "tg-Cyrl",
                    "7C2E": "dsb",
                    "7C3B": "smj",
                    "7C3F": "kk-Latn, reserved",
                    "7C43": "uz-Latn",
                    "7C46": "pa-Arab",
                    "7C50": "mn-Mong",
                    "7C59": "sd-Arab",
                    "7C5C": "chr-Cher",
                    "7C5D": "iu-Latn",
                    "7C5F": "tzm-Latn",
                    "7C67": "ff-Latn",
                    "7C68": "ha-Latn",
                    "7C92": "ku-Arab",
                    "F2EE": "reserved",
                    "E40C": "fr-015, reserved",
                    "EEEE": "reserved",
                }
                language = languages.get(language, "Invalid")
                sublanguage = file.read(8).upper()
                data += sublanguage
                if sublanguage == b"0\x004\x00B\x000\x00":
                    sublanguage = "Unicode"
                elif sublanguage == b"0\x000\x000\x000\x00":
                    sublanguage = "7-bit ASCII"
                elif sublanguage == b"0\x003\x00A\x004\x00":
                    sublanguage = "Japan (Shift ? JIS X-0208)"
                elif sublanguage == b"0\x003\x00B\x005\x00":
                    sublanguage = "Korea (Shift ? KSC 5601)"
                elif sublanguage == b"0\x003\x00B\x006\x00":
                    sublanguage = "Taiwan (Big5)"
                elif sublanguage == b"0\x004\x00E\x002\x00":
                    sublanguage = "Latin-2 (Eastern European)"
                elif sublanguage == b"0\x004\x00E\x003\x00":
                    sublanguage = "Cyrillic"
                elif sublanguage == b"0\x004\x00E\x004\x00":
                    sublanguage = "Multilingual"
                elif sublanguage == b"0\x004\x00E\x005\x00":
                    sublanguage = "Greek"
                elif sublanguage == b"0\x004\x00E\x006\x00":
                    sublanguage = "Turkish"
                elif sublanguage == b"0\x004\x00E\x007\x00":
                    sublanguage = "Hebrew"
                elif sublanguage == b"0\x004\x00E\x008\x00":
                    sublanguage = "Arabic"
                else:
                    sublanguage = "Unknown"
                print(
                    "Language".ljust(25),
                    f"{position+6:0>8x}-{position+22:0>8x}".ljust(20),
                    hexlify(data).decode().ljust(40),
                    "".join(
                        chr(x) if x in printable else "." for x in data
                    ).ljust(20),
                    language,
                    ";",
                    sublanguage,
                )
                entryend = position + entrylength
                position += 22
                get_attribute()

            if string == b"VarFileInfo":
                read_VarFileInfo()
            elif string == b"StringFileInfo":
                read_StringFileInfo()
            char = file.read(1)
            while char == "\0":
                position += 1
                char = file.read(1)
            data_length = char + file.read(1)
            data_valuelength = file.read(2)
            data_type = file.read(2)
            length = int.from_bytes(data_length, "little")
            valuelength = int.from_bytes(data_valuelength, "little")
            type_ = int.from_bytes(data_type, "little")
            print(
                "Version child length".ljust(25),
                f"{position:0>8x}-{position+2:0>8x}".ljust(20),
                hexlify(data_length).decode().ljust(40),
                "".join(
                    chr(x) if x in printable else "." for x in data_length
                ).ljust(20),
                length,
            )
            print(
                "Version child value length".ljust(25),
                f"{position+2:0>8x}-{position+4:0>8x}".ljust(20),
                hexlify(data_valuelength).decode().ljust(40),
                "".join(
                    chr(x) if x in printable else "." for x in data_valuelength
                ).ljust(20),
                valuelength,
            )
            print(
                "Version child type".ljust(25),
                f"{position+4:0>8x}-{position+6:0>8x}".ljust(20),
                hexlify(data_type).decode().ljust(40),
                "".join(
                    chr(x) if x in printable else "." for x in data_type
                ).ljust(20),
                type_,
            )
            position += 6
            string = b""
            start_string_position = position
            precedent_char = b"\0"
            char = file.read(1)
            position += 1
            while char != b"\0" or precedent_char != b"\0":
                string += char
                precedent_char = char
                char = file.read(1)
                position += 1
            string = string.replace(b"\0", b"")
            if len(string) <= 20:
                data = hexlify(string).decode().ljust(40)
            else:
                data = "\b"
            print(
                "Version child key".ljust(25),
                f"{start_string_position:0>8x}-{position:0>8x}".ljust(20),
                data,
                "".join(
                    chr(x) if x in printable else "." for x in string
                ).ljust(20),
            )
            if string == b"VarFileInfo":
                read_VarFileInfo()
            elif string == b"StringFileInfo":
                read_StringFileInfo()
            print(
                "\n", f"{' Version end - In resources ':*^139}", "\n", sep=""
            )

        return size

    def read_resources_headers(main=False):
        global position, last_object
        data = file.read(4)
        time_ = file.read(4)
        if any(time_):
            return
        print(
            "Characteristics".ljust(25),
            f"{position:0>8x}-{position+4:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            int.from_bytes(data, "little"),
        )
        data = time_
        print(
            "Timestamp".ljust(25),
            f"{position+4:0>8x}-{position+8:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            ctime(int.from_bytes(data, "little")),
        )
        data = file.read(2)
        print(
            "Major version".ljust(25),
            f"{position+8:0>8x}-{position+10:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            int.from_bytes(data, "little"),
        )
        data = file.read(2)
        print(
            "Minor version".ljust(25),
            f"{position+10:0>8x}-{position+12:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            int.from_bytes(data, "little"),
        )
        data = file.read(2)
        named_entries = int.from_bytes(data, "little")
        vprint(
            "Named entries number".ljust(25),
            f"{position+12:0>8x}-{position+14:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            named_entries,
        )
        data = file.read(2)
        id_entries = int.from_bytes(data, "little")
        vprint(
            "ID entries number".ljust(25),
            f"{position+14:0>8x}-{position+16:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            id_entries,
        )
        position += 16
        if not id_entries:
            return None
        for entry in range(named_entries + id_entries):
            if position > 0:
                file.seek(position)
                type_int, offset = read_base_entry()
                if offset:
                    position = data_position + offset
                    file.seek(position)
                    if type_int:
                        read_resources_headers()
                    else:
                        size = read_data_entry()
                        if size != 16 and size != 8:
                            return None

            if not main:
                break

            position = data_position + 16 + 8 * (entry + 1)
            last_object = None

    if position < filesize:
        print("\n", f"{' Resources ':*^139}", "\n", sep="")
        read_resources_headers(True)
    if rva_export and size_export:
        print("\n", f"{' Functions exported ':*^139}", "\n", sep="")
        position = rva_export - export_virtual_address + export_data_position
        file.seek(position)
        data = file.read(4)
        vprint(
            "Export Flags".ljust(25),
            f"{position:0>8x}-{position+4:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            int.from_bytes(data, "little"),
        )
        data = file.read(4)
        print(
            "DateTimeStamp".ljust(25),
            f"{position+4:0>8x}-{position+8:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            ctime(int.from_bytes(data, "little")),
        )
        data = file.read(2)
        print(
            "MajorVersion".ljust(25),
            f"{position+8:0>8x}-{position+10:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            int.from_bytes(data, "little"),
        )
        data = file.read(2)
        print(
            "MinorVersion".ljust(25),
            f"{position+10:0>8x}-{position+12:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            int.from_bytes(data, "little"),
        )
        data = file.read(4)
        name_address = int.from_bytes(data, "little")
        vprint(
            "DLL name address".ljust(25),
            f"{position+12:0>8x}-{position+16:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            name_address,
        )
        if name_address:
            saved_position = file.tell()
            start_position = position = (
                name_address - export_virtual_address + export_data_position
            )
            file.seek(position)
            data = b""
            char = file.read(1)
            while char != b"\0":
                data += char
                char = file.read(1)
                position += 1
            print(
                "DLL Name".ljust(25),
                f"{start_position:0>8x}-{position:0>8x}".ljust(20),
                hexlify(data).decode().ljust(40) if len(data) < 20 else "\b",
                "".join(chr(x) if x in printable else "." for x in data).ljust(
                    20
                ),
            )
            file.seek(saved_position)
            position = saved_position - 16
        data = file.read(4)
        ordinal_base = int.from_bytes(data, "little")
        print(
            "Ordinal base".ljust(25),
            f"{position+16:0>8x}-{position+20:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            ordinal_base,
        )
        data = file.read(4)
        functions_number = int.from_bytes(data, "little")
        print(
            "Number of functions".ljust(25),
            f"{position+20:0>8x}-{position+24:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            functions_number,
        )
        data = file.read(4)
        names_number = int.from_bytes(data, "little")
        print(
            "Number of names".ljust(25),
            f"{position+24:0>8x}-{position+28:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            names_number,
        )
        data = file.read(4)
        vprint(
            "Functions address".ljust(25),
            f"{position+28:0>8x}-{position+32:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            int.from_bytes(data, "little"),
        )
        data = file.read(4)
        names_adress = int.from_bytes(data, "little")
        vprint(
            "Names address".ljust(25),
            f"{position+32:0>8x}-{position+36:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            name_address,
        )
        data = file.read(4)
        ordinals_address = int.from_bytes(data, "little")
        vprint(
            "Ordinals address".ljust(25),
            f"{position+36:0>8x}-{position+40:0>8x}".ljust(20),
            hexlify(data).decode().ljust(40),
            "".join(chr(x) if x in printable else "." for x in data).ljust(20),
            ordinals_address,
        )
        position += 40
        functions_names = []
        for name_index in range(names_number):
            position = (
                names_adress - export_virtual_address + export_data_position
            )
            file.seek(position)
            data = file.read(4)
            position = (
                int.from_bytes(data, "little")
                - export_virtual_address
                + export_data_position
            )
            file.seek(position)
            start_string_position = position
            data = file.read(2)
            char = file.read(1)
            position += 3
            while char != b"\0":
                data += char
                position += 1
                char = file.read(1)
            function_name = "".join(
                chr(x) if x in printable else "." for x in data
            ).ljust(20)
            print(
                "Function name".ljust(25),
                f"{start_string_position:0>8x}-{position:0>8x}".ljust(20),
                hexlify(data).decode().ljust(40) if len(data) < 20 else "\b",
                function_name,
            )
            functions_names.append(function_name)
            names_adress += 4
        if ordinals_address:
            position = (
                ordinals_address
                - export_virtual_address
                + export_data_position
            )
            file.seek(position)
            # for function_index in range(functions_number - names_number):
            for function_index, name in enumerate(functions_names):
                data = file.read(2)
                print(
                    "Ordinal".ljust(25),
                    f"{position:0>8x}-{position+2:0>8x}".ljust(20),
                    hexlify(data).decode().ljust(40),
                    str(int.from_bytes(data, "little") + ordinal_base)
                    + " "
                    + name,
                )
                position += 2
    if exe_architecture == 64:
        address_length = 6
    else:
        address_length = 2
    if rva_import and size_import:
        print("\n", f"{' Functions imported ':*^139}", "\n", sep="")
        position = rva_import - import_virtual_address + import_data_position
        original_thunk = datetime = forwardchain = name_address = thunk = 1
        while (
            original_thunk != 0
            or datetime != 0
            or forwardchain != 0
            or name_address != 0
            or thunk != 0
        ):
            file.seek(position)
            data = file.read(4)
            original_thunk = int.from_bytes(data, "little")
            vprint(
                "OriginalFirstThunk".ljust(25),
                f"{position:0>8x}-{position+4:0>8x}".ljust(20),
                hexlify(data).decode().ljust(40),
                "".join(chr(x) if x in printable else "." for x in data).ljust(
                    20
                ),
                original_thunk,
            )
            data = file.read(4)
            datetime = int.from_bytes(data, "little")
            print(
                "DateTimeStamp".ljust(25),
                f"{position+4:0>8x}-{position+8:0>8x}".ljust(20),
                hexlify(data).decode().ljust(40),
                "".join(chr(x) if x in printable else "." for x in data).ljust(
                    20
                ),
                ctime(datetime),
            )
            data = file.read(4)
            forwardchain = int.from_bytes(data, "little")
            vprint(
                "ForwarderChain".ljust(25),
                f"{position+8:0>8x}-{position+12:0>8x}".ljust(20),
                hexlify(data).decode().ljust(40),
                "".join(chr(x) if x in printable else "." for x in data).ljust(
                    20
                ),
                forwardchain,
            )
            data = file.read(4)
            name_address = int.from_bytes(data, "little")
            vprint(
                "Name address".ljust(25),
                f"{position+12:0>8x}-{position+16:0>8x}".ljust(20),
                hexlify(data).decode().ljust(40),
                "".join(chr(x) if x in printable else "." for x in data).ljust(
                    20
                ),
                name_address,
            )
            if name_address:
                saved_position = file.tell()
                if (
                    import_virtual_address
                    <= name_address
                    <= (import_virtual_address + import_virtual_size)
                ):
                    data_position = import_data_position
                    virtual_address = import_virtual_address
                else:
                    data_position, virtual_address = [
                        (x.start_position, x.virtual_address)
                        for x in sections
                        if x.virtual_address
                        <= name_address
                        <= (x.virtual_size + x.virtual_address)
                    ][0]
                start_position = position = (
                    name_address - virtual_address + data_position
                )
                file.seek(position)
                data = b""
                char = file.read(1)
                while char != b"\0":
                    data += char
                    char = file.read(1)
                    position += 1
                print(
                    "Name".ljust(25),
                    f"{start_position:0>8x}-{position:0>8x}".ljust(20),
                    hexlify(data).decode().ljust(40)
                    if len(data) < 20
                    else "\b",
                    "".join(
                        chr(x) if x in printable else "." for x in data
                    ).ljust(20),
                )
                file.seek(saved_position)
                position = saved_position - 16
            data = file.read(4)
            thunk = int.from_bytes(data, "little")
            vprint(
                "FirstThunk".ljust(25),
                f"{position+16:0>8x}-{position+20:0>8x}".ljust(20),
                hexlify(data).decode().ljust(40),
                "".join(chr(x) if x in printable else "." for x in data).ljust(
                    20
                ),
                thunk,
            )
            position += 20
            saved_position = position
            if original_thunk:
                position = original_thunk - virtual_address + data_position
            elif thunk:
                position = thunk - virtual_address + data_position
            else:
                continue
            file.seek(position)
            address = file.read(2)
            while address != b"\0\0":
                data = address + file.read(address_length)
                if data.endswith(b"\0\x80"):
                    ordinal = int.from_bytes(data[:-2], "little")
                    print(
                        "Ordinal".ljust(25),
                        f"{position:0>8x}-{position+address_length+2:0>8x}".ljust(
                            20
                        ),
                        hexlify(data).decode().ljust(40),
                        "".join(
                            chr(x) if x in printable else "." for x in data
                        ).ljust(20),
                        hex(ordinal),
                    )
                else:
                    position = (
                        int.from_bytes(data, "little")
                        - virtual_address
                        + data_position
                    )
                    if 0 >= position or position >= filesize:
                        position = file.tell()
                        print(
                            "Function unknown".ljust(25),
                            f"{position-2:0>8x}-{position:0>8x}".ljust(20),
                            hexlify(address).decode().ljust(40),
                            "".join(
                                chr(x) if x in printable else "."
                                for x in address
                            ).ljust(20),
                            "Address:",
                            position,
                        )
                        address = file.read(2)
                        continue
                    saved_position2 = file.tell()
                    file.seek(position)
                    file.read(2)
                    position += 2
                    start_string_position = position
                    position += 1
                    data = b""
                    char = file.read(1)
                    while char != b"\0":
                        data += char
                        position += 1
                        char = file.read(1)
                    print(
                        "Function name".ljust(25),
                        f"{start_string_position:0>8x}-{position:0>8x}".ljust(
                            20
                        ),
                        hexlify(data).decode().ljust(40)
                        if len(data) <= 20
                        else "\b",
                        "".join(
                            chr(x) if x in printable else "." for x in data
                        ).ljust(20),
                    )
                    position = saved_position2
                    file.seek(position)
                address = file.read(2)
            position = saved_position

    overlay_position = max([x.start_position + x.size for x in sections])
    file.seek(overlay_position)
    if file.read(1):
        file.seek(overlay_position)
        try:
            with open("overlay_" + basename(argv[1]), "wb") as overlay:
                copyfileobj(file, overlay)
        except PermissionError:
            print("Permission Denied to extract overlay.", file=stderr)
    if entropy_charts_import:
        axes = pyplot.gca()
        axes.invert_yaxis()
        axes.xaxis.set_visible(False)
        axes.set_xlim(
            0,
            max(
                max([x.virtual_address + x.virtual_size for x in sections]),
                overlay_position,
            ),
        )
        for section in sections:
            axes.barh(
                ("Memory", "File"),
                (section.virtual_size, section.size),
                left=(section.virtual_address, section.start_position),
                color=section.color,
                label=section.label,
            )
        axes.legend(
            ncols=2,
            bbox_to_anchor=(0, 1),
            loc="lower left",
            fontsize="small",
        )
        pyplot.title(
            "Compare sections size in memory and sections size on disk"
        )
        pyplot.show()
        file.seek(0)
        charts_chunks_file_entropy(
            file, part_size=round(filesize / 100), sections=sections
        )

"""Bypass modules for Waf."""
from .cloudflare_waf import CloudflareWAFBypass
from .fastly_waf import FastlyWafBypass
from .aws_waf import AWSWAFBypass
from .azure_waf import AzureWAFBypass
from .gcp_armor import GcpArmorBypass
from .imperva import ImpervaBypass
from .f5_asm import F5AsmBypass
from .barracuda import BarracudaBypass
from .fortinet import FortinetBypass
from .radware import RadwareBypass
from .wordfence import WordfenceBypass
from .sucuri_waf import SucuriWAFBypass
from .modsecurity import ModSecurityBypass
from .naxsi import NaxsiBypass
from .citrix_netscaler import CitrixNetscalerBypass
from .alibaba import AlibabaBypass
from .huawei import HuaweiBypass
from .tencent import TencentBypass
from .baidu import BaiduBypass
from .comodo import ComodoBypass
from .sitelock import SitelockBypass
from .zenedge import ZenedgeBypass
from .oracle import OracleBypass
from .ibm import IbmBypass
from .apptrana import ApptranaBypass
from .webknight import WebknightBypass
from .patchstack import PatchstackBypass
from .nsfocus import NsfocusBypass
from .sangfor import SangforBypass
from .hillstone import HillstoneBypass
from .yundun import YundunBypass
from .qihoo360 import Qihoo360Bypass
from .anquanbao import AnquanbaoBypass
from .jetoctopus import JetoctopusBypass
from .imunify360 import Imunify360Bypass
from .cxs_lfd import CxsLfdBypass
from .bitninja import BitninjaBypass
from .malcare import MalcareBypass
from .ninjafirewall import NinjafirewallBypass
from .securiwaf import SecuriwafBypass
from .webarx import WebarxBypass
from .astra import AstraBypass
from .safe3 import Safe3Bypass
from .shadowdaemon import ShadowdaemonBypass
from .ironbee import IronbeeBypass
from .phpids import PhpidsBypass
from .seal import SealBypass

__all__ = [
    "CloudflareWAFBypass",
    "FastlyWafBypass",
    "AWSWAFBypass",
    "AzureWAFBypass",
    "GcpArmorBypass",
    "ImpervaBypass",
    "F5AsmBypass",
    "BarracudaBypass",
    "FortinetBypass",
    "RadwareBypass",
    "WordfenceBypass",
    "SucuriWAFBypass",
    "ModSecurityBypass",
    "NaxsiBypass",
    "CitrixNetscalerBypass",
    "AlibabaBypass",
    "HuaweiBypass",
    "TencentBypass",
    "BaiduBypass",
    "ComodoBypass",
    "SitelockBypass",
    "ZenedgeBypass",
    "OracleBypass",
    "IbmBypass",
    "ApptranaBypass",
    "WebknightBypass",
    "PatchstackBypass",
    "NsfocusBypass",
    "SangforBypass",
    "HillstoneBypass",
    "YundunBypass",
    "Qihoo360Bypass",
    "AnquanbaoBypass",
    "JetoctopusBypass",
    "Imunify360Bypass",
    "CxsLfdBypass",
    "BitninjaBypass",
    "MalcareBypass",
    "NinjafirewallBypass",
    "SecuriwafBypass",
    "WebarxBypass",
    "AstraBypass",
    "Safe3Bypass",
    "ShadowdaemonBypass",
    "IronbeeBypass",
    "PhpidsBypass",
    "SealBypass"
]

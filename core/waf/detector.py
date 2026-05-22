"""
NOIR v7.0 - WAF Detector Module
Detects and identifies WAF systems (MalCare, Cloudflare, Wordfence, etc.)
"""
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Set
from enum import Enum


class WAFType(Enum):
    NONE = "none"
    MALCARE = "malcare"
    CLOUDFLARE = "cloudflare"
    WORDFENCE = "wordfence"
    SUCURI = "sucuri"
    AKAMAI = "akamai"
    INCAPSULA = "incapsula"
    AWS_WAF = "aws_waf"
    AZURE_WAF = "azure_waf"
    UNKNOWN = "unknown"


class BlockReason(Enum):
    NONE = "none"
    IP_BLOCKED = "ip_blocked"
    RATE_LIMITED = "rate_limited"
    CHALLENGE = "challenge"
    CAPTCHA = "captcha"
    WAF_RULE = "waf_rule"
    BOT_DETECTED = "bot_detected"


@dataclass
class WAFDetectionResult:
    """Result of WAF detection"""
    detected: bool
    waf_type: WAFType
    confidence: float
    block_reason: BlockReason
    is_blocking: bool
    response_indicators: List[str]
    headers: Dict[str, str]


class WAFDetector:
    """Advanced WAF detection engine"""
    
    SIGNATURES = {
        WAFType.MALCARE: {
            "body": ["MalCare", "malcare.io", "mc_request_id", "blocked by MalCare", "MalCare Security"],
            "headers": ["x-malcare", "mc-request-id"],
            "status_codes": [403, 503]
        },
        WAFType.CLOUDFLARE: {
            "body": ["cloudflare", "cf-ray", "__cf_bm", "cf_clearance", "Checking your browser", "Ray ID"],
            "headers": ["cf-ray", "cf-cache-status", "cf-request-id"],
            "status_codes": [403, 503, 429, 307]
        },
        WAFType.WORDFENCE: {
            "body": ["wordfence", "wf_logkey", "Wordfence Security"],
            "headers": ["x-wordfence"],
            "status_codes": [403]
        },
        WAFType.SUCURI: {
            "body": ["sucuri", "Sucuri Website Firewall", "Access Denied"],
            "headers": ["x-sucuri", "x-sucuri-id"],
            "status_codes": [403, 406]
        },
    }
    
    def __init__(self):
        self.detection_history = []
    
    def detect(self, response_status, response_headers, response_body):
        indicators = []
        detected_wafs = {}
        
        for waf_type, signatures in self.SIGNATURES.items():
            score = 0.0
            max_score = 0
            
            for sig in signatures.get("body", []):
                max_score += 1
                if sig.lower() in response_body.lower():
                    score += 1
                    indicators.append(f"Body: {sig}")
            
            for sig in signatures.get("headers", []):
                max_score += 1
                for header_name, header_value in response_headers.items():
                    if sig.lower() in header_name.lower() or sig.lower() in header_value.lower():
                        score += 1
                        indicators.append(f"Header: {sig}")
                        break
            
            for status in signatures.get("status_codes", []):
                max_score += 0.5
                if response_status == status:
                    score += 0.5
                    indicators.append(f"Status: {status}")
            
            if max_score > 0:
                confidence = score / max_score
                if confidence > 0.3:
                    detected_wafs[waf_type] = confidence
        
        if detected_wafs:
            primary_waf = max(detected_wafs, key=detected_wafs.get)
            confidence = detected_wafs[primary_waf]
        else:
            primary_waf = WAFType.NONE
            confidence = 0.0
        
        is_blocking = response_status in [403, 503, 429, 307]
        block_reason = self._get_block_reason(response_status, response_body, is_blocking)
        
        result = WAFDetectionResult(
            detected=primary_waf != WAFType.NONE,
            waf_type=primary_waf,
            confidence=confidence,
            block_reason=block_reason,
            is_blocking=is_blocking,
            response_indicators=list(set(indicators)),
            headers=dict(response_headers),
        )
        
        self.detection_history.append(result)
        return result
    
    def _get_block_reason(self, status, body, is_blocking):
        if not is_blocking:
            return BlockReason.NONE
        if "captcha" in body.lower():
            return BlockReason.CAPTCHA
        if "challenge" in body.lower():
            return BlockReason.CHALLENGE
        if status == 429:
            return BlockReason.RATE_LIMITED
        if status == 403:
            return BlockReason.IP_BLOCKED
        return BlockReason.WAF_RULE


# Global detector instance
waf_detector = WAFDetector()

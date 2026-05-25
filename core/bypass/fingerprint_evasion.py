"""
Advanced Fingerprinting Evasion - 2026
Bypass TLS fingerprinting (JA3/JA4), Canvas, WebGL, Audio Context, and other
browser fingerprinting techniques used by Cloudflare and modern WAFs.
"""
import hashlib
import random
import json
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field


@dataclass
class TLSFingerprint:
    """TLS fingerprint configuration for JA3/JA4 evasion."""
    version: str
    ciphers: List[str]
    extensions: List[int]
    curves: List[int]
    point_formats: List[int]
    
    def to_ja3_string(self) -> str:
        """Generate JA3 fingerprint string."""
        version_map = {'TLS1.2': '771', 'TLS1.3': '772'}
        version_code = version_map.get(self.version, '771')
        
        cipher_str = '-'.join(str(c) for c in self.ciphers)
        ext_str = '-'.join(str(e) for e in self.extensions)
        curve_str = '-'.join(str(c) for c in self.curves)
        pf_str = '-'.join(str(p) for p in self.point_formats)
        
        ja3_str = f"{version_code},{cipher_str},{ext_str},{curve_str},{pf_str}"
        return hashlib.md5(ja3_str.encode()).hexdigest()


class FingerprintProfiles:
    """Collection of real browser fingerprints."""
    
    CHROME_120_WINDOWS = TLSFingerprint(
        version='TLS1.3',
        ciphers=[4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156, 157, 47, 53],
        extensions=[0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 17513, 21],
        curves=[29, 23, 24, 25, 256, 257],
        point_formats=[0]
    )
    
    CHROME_121_MACOS = TLSFingerprint(
        version='TLS1.3',
        ciphers=[4865, 4866, 4867, 49195, 49199, 52393, 52392, 49196, 49200, 49162, 49161, 49171, 49172, 156, 157, 47, 53],
        extensions=[0, 23, 65281, 10, 11, 35, 16, 5, 34, 51, 43, 13, 45, 28, 65037],
        curves=[29, 23, 24],
        point_formats=[0]
    )
    
    FIREFOX_122_WINDOWS = TLSFingerprint(
        version='TLS1.3',
        ciphers=[4865, 4867, 4866, 49195, 49199, 52393, 52392, 49196, 49200, 49162, 49161, 49171, 49172, 156, 157, 47, 53],
        extensions=[0, 23, 65281, 10, 11, 35, 16, 5, 34, 51, 43, 13, 45, 28],
        curves=[29, 23, 24, 25],
        point_formats=[0]
    )
    
    EDGE_120_WINDOWS = TLSFingerprint(
        version='TLS1.3',
        ciphers=[4865, 4866, 4867, 49196, 49195, 52393, 49200, 49199, 49162, 49161, 49172, 49171, 157, 156, 53, 47],
        extensions=[0, 23, 65281, 10, 11, 16, 5, 13, 18, 51, 45, 43, 27, 17513, 21],
        curves=[29, 23, 24, 25],
        point_formats=[0]
    )
    
    @classmethod
    def get_random_profile(cls) -> TLSFingerprint:
        """Get random browser fingerprint."""
        profiles = [
            cls.CHROME_120_WINDOWS,
            cls.CHROME_121_MACOS,
            cls.FIREFOX_122_WINDOWS,
            cls.EDGE_120_WINDOWS
        ]
        return random.choice(profiles)
    
    @classmethod
    def mutate_profile(cls, profile: TLSFingerprint) -> TLSFingerprint:
        """Slightly mutate fingerprint for uniqueness while maintaining validity."""
        new_profile = TLSFingerprint(
            version=profile.version,
            ciphers=profile.ciphers.copy(),
            extensions=profile.extensions.copy(),
            curves=profile.curves.copy(),
            point_formats=profile.point_formats.copy()
        )
        
        # Randomly shuffle cipher order (maintains validity)
        if random.random() < 0.3:
            random.shuffle(new_profile.ciphers)
        
        # Randomly add/remove non-critical extensions
        if random.random() < 0.2:
            optional_exts = [17513, 21, 28, 34, 45]
            ext_to_add = random.choice(optional_exts)
            if ext_to_add not in new_profile.extensions:
                new_profile.extensions.append(ext_to_add)
        
        return new_profile


@dataclass
class CanvasFingerprint:
    """Canvas fingerprinting evasion."""
    
    @staticmethod
    def generate_noise_pattern() -> Dict[str, float]:
        """Generate subtle noise to add to canvas rendering."""
        return {
            'red_shift': random.uniform(-0.0001, 0.0001),
            'green_shift': random.uniform(-0.0001, 0.0001),
            'blue_shift': random.uniform(-0.0001, 0.0001),
            'alpha_shift': random.uniform(-0.00005, 0.00005)
        }
    
    @staticmethod
    def get_canvas_script() -> str:
        """JavaScript to inject canvas noise."""
        noise = CanvasFingerprint.generate_noise_pattern()
        return f"""
        (function() {{
            const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
            const originalGetImageData = CanvasRenderingContext2D.prototype.getImageData;
            
            HTMLCanvasElement.prototype.toDataURL = function() {{
                const context = this.getContext('2d');
                const imageData = context.getImageData(0, 0, this.width, this.height);
                const data = imageData.data;
                
                for (let i = 0; i < data.length; i += 4) {{
                    data[i] += {noise['red_shift']};
                    data[i+1] += {noise['green_shift']};
                    data[i+2] += {noise['blue_shift']};
                    data[i+3] += {noise['alpha_shift']};
                }}
                
                context.putImageData(imageData, 0, 0);
                return originalToDataURL.apply(this, arguments);
            }};
        }})();
        """


@dataclass
class WebGLFingerprint:
    """WebGL fingerprinting evasion."""
    
    @staticmethod
    def get_webgl_script() -> str:
        """JavaScript to randomize WebGL parameters."""
        vendor = random.choice([
            'Intel Inc.',
            'NVIDIA Corporation',
            'AMD',
            'Apple Inc.'
        ])
        
        renderer = random.choice([
            'Intel(R) UHD Graphics 630',
            'NVIDIA GeForce RTX 3060',
            'AMD Radeon RX 6700 XT',
            'Apple M1'
        ])
        
        return f"""
        (function() {{
            const getParameter = WebGLRenderingContext.prototype.getParameter;
            WebGLRenderingContext.prototype.getParameter = function(parameter) {{
                if (parameter === 37445) {{
                    return '{vendor}';
                }}
                if (parameter === 37446) {{
                    return '{renderer}';
                }}
                return getParameter.apply(this, arguments);
            }};
            
            const getParameter2 = WebGL2RenderingContext.prototype.getParameter;
            WebGL2RenderingContext.prototype.getParameter = function(parameter) {{
                if (parameter === 37445) {{
                    return '{vendor}';
                }}
                if (parameter === 37446) {{
                    return '{renderer}';
                }}
                return getParameter2.apply(this, arguments);
            }};
        }})();
        """


@dataclass
class AudioContextFingerprint:
    """Audio context fingerprinting evasion."""
    
    @staticmethod
    def get_audio_script() -> str:
        """JavaScript to add noise to audio context."""
        noise_level = random.uniform(0.00001, 0.0001)
        return f"""
        (function() {{
            const audioContext = window.AudioContext || window.webkitAudioContext;
            if (!audioContext) return;
            
            const originalCreateOscillator = audioContext.prototype.createOscillator;
            audioContext.prototype.createOscillator = function() {{
                const oscillator = originalCreateOscillator.apply(this, arguments);
                const originalStart = oscillator.start;
                oscillator.start = function() {{
                    oscillator.frequency.value += {noise_level};
                    return originalStart.apply(this, arguments);
                }};
                return oscillator;
            }};
        }})();
        """


@dataclass
class FontFingerprint:
    """Font fingerprinting evasion."""
    
    @staticmethod
    def get_common_fonts() -> List[str]:
        """Return list of common fonts to report."""
        base_fonts = [
            'Arial', 'Verdana', 'Helvetica', 'Times New Roman', 'Courier New',
            'Georgia', 'Palatino', 'Garamond', 'Bookman', 'Comic Sans MS',
            'Trebuchet MS', 'Impact'
        ]
        
        # Randomly include/exclude some fonts
        return [f for f in base_fonts if random.random() > 0.2]


class FingerprintManager:
    """Manage all fingerprinting evasion techniques."""
    
    def __init__(self):
        self.tls_profile = FingerprintProfiles.get_random_profile()
        self.canvas_noise = CanvasFingerprint.generate_noise_pattern()
        self.session_fingerprints: Dict[str, Dict] = {}
    
    def get_session_fingerprint(self, session_id: str) -> Dict:
        """Get or create consistent fingerprint for session."""
        if session_id not in self.session_fingerprints:
            self.session_fingerprints[session_id] = self._generate_fingerprint()
        return self.session_fingerprints[session_id]
    
    def _generate_fingerprint(self) -> Dict:
        """Generate complete browser fingerprint."""
        tls = FingerprintProfiles.mutate_profile(
            FingerprintProfiles.get_random_profile()
        )
        
        return {
            'tls': {
                'ja3': tls.to_ja3_string(),
                'version': tls.version,
                'ciphers': tls.ciphers
            },
            'canvas_script': CanvasFingerprint.get_canvas_script(),
            'webgl_script': WebGLFingerprint.get_webgl_script(),
            'audio_script': AudioContextFingerprint.get_audio_script(),
            'fonts': FontFingerprint.get_common_fonts(),
            'screen': {
                'width': random.choice([1920, 2560, 1366, 1440]),
                'height': random.choice([1080, 1440, 768, 900]),
                'color_depth': random.choice([24, 32]),
                'pixel_ratio': random.choice([1, 1.5, 2])
            },
            'timezone': random.choice([
                'America/New_York', 'America/Los_Angeles', 'Europe/London',
                'Europe/Paris', 'Asia/Tokyo', 'Asia/Shanghai'
            ]),
            'language': random.choice([
                'en-US', 'en-GB', 'fr-FR', 'de-DE', 'ja-JP', 'zh-CN'
            ]),
            'platform': random.choice([
                'Win32', 'MacIntel', 'Linux x86_64'
            ]),
            'hardware_concurrency': random.choice([4, 8, 12, 16]),
            'device_memory': random.choice([4, 8, 16, 32])
        }
    
    def get_injection_scripts(self, session_id: str) -> List[str]:
        """Get all JavaScript injection scripts for fingerprint evasion."""
        fp = self.get_session_fingerprint(session_id)
        
        scripts = [
            fp['canvas_script'],
            fp['webgl_script'],
            fp['audio_script']
        ]
        
        # Add navigator overrides
        scripts.append(f"""
        Object.defineProperty(navigator, 'hardwareConcurrency', {{
            get: () => {fp['hardware_concurrency']}
        }});
        Object.defineProperty(navigator, 'deviceMemory', {{
            get: () => {fp['device_memory']}
        }});
        Object.defineProperty(navigator, 'platform', {{
            get: () => '{fp['platform']}'
        }});
        Object.defineProperty(navigator, 'language', {{
            get: () => '{fp['language']}'
        }});
        """)
        
        return scripts
    
    def rotate_fingerprint(self, session_id: str) -> None:
        """Generate new fingerprint for session."""
        if session_id in self.session_fingerprints:
            del self.session_fingerprints[session_id]


# Global manager instance
_manager = None

def get_fingerprint_manager() -> FingerprintManager:
    """Get global fingerprint manager instance."""
    global _manager
    if _manager is None:
        _manager = FingerprintManager()
    return _manager

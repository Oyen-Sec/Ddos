CMS_PATTERNS = {
    "wordpress": {
        "detect": ["wp-content", "wp-json", "wp-includes", "wordpress"],
        "heavy": [
            "/",
            "/wp-json/wp/v2/posts",
            "/wp-admin/admin-ajax.php",
            "/?s=test"
        ],
        "medium": ["/wp-login.php", "/wp-json/wp/v2/users"],
        "light": ["/"],
        "filter": ["/wp-content/", "/wp-includes/", "/wp-admin/*.js", "/wp-admin/*.css", "*.js", "*.css", "*.png", "*.jpg"]
    },
    "shopify": {
        "detect": ["cdn.shopify.com", "myshopify", "shopify"],
        "heavy": ["/cart/add.js", "/cart/update.js", "/search?q=test"],
        "medium": ["/products.json", "/collections/all"],
        "light": ["/"],
        "filter": ["/cdn.shopify.com/", "*.js", "*.css"]
    },
    "squarespace": {
        "detect": ["assets.squarespace.com", "static.squarespace.com", "squarespace"],
        "heavy": ["/api/search", "/api/comments", "/api/commerce/inventory"],
        "medium": ["/"],
        "light": ["/static/*"],
        "filter": ["/assets.squarespace.com/", "/universal/scripts-compressed/", "*.js", "*.css"]
    },
    "wix": {
        "detect": ["_api/wix-public-html-webapp", "wixstatic", "wix"],
        "heavy": ["/_api/wix-public-html-webapp/site-data", "/_api/communities-blog-node-api/_api/posts"],
        "medium": ["/"],
        "light": ["/_partials/*"],
        "filter": ["/_partials/", "/static/", "*.js", "*.css"]
    },
    "generic": {
        "detect": [],
        "heavy": ["/search", "/api/search", "/graphql", "/login"],
        "medium": ["/api/*", "/rest/*", "/v1/*"],
        "light": ["/"],
        "filter": ["/static/", "/assets/", "/cdn/", "*.js", "*.css", "*.png", "*.jpg", "*.gif", "*.svg", "*.woff", "*.ttf"]
    }
}

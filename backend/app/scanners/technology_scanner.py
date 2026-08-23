"""
Technology Scanner for Sentinel.

Detects technologies, frameworks, and libraries used by the target website:
- Web servers (nginx, Apache, IIS, etc.)
- Programming languages (PHP, Python, Ruby, etc.)
- Frameworks (React, Angular, Vue, Django, Rails, etc.)
- JavaScript libraries (jQuery, Bootstrap, etc.)
- CMS platforms (WordPress, Drupal, Joomla, etc.)
- CDN and hosting providers
- Analytics and tracking tools
"""

import re
from typing import List, Dict, Any, Optional, Set
from urllib.parse import urlparse

from app.scanners.base import BaseScanner


class TechnologyScanner(BaseScanner):
    """
    Technology Scanner.

    Detects technologies used by the target website through:
    - HTTP headers
    - HTML meta tags
    - JavaScript file names
    - CSS file names
    - HTML comments
    - Cookie names
    - Response content patterns
    """

    def get_scanner_name(self) -> str:
        """Get the scanner name."""
        return "technology"

    async def scan(self) -> List[Dict[str, Any]]:
        """
        Execute the technology scan.

        Returns:
            List of findings.
        """
        self._log_info(f"Starting technology scan for {self.target_url}")
        self.findings = []
        self.detected_technologies: Dict[str, List[str]] = {}

        try:
            client = await self._get_client()
            response = await client.get(self.target_url, follow_redirects=True)

            headers = response.headers
            content = response.text

            # Detect technologies from headers
            await self._detect_from_headers(headers)

            # Detect technologies from HTML
            await self._detect_from_html(content)

            # Detect technologies from JavaScript/CSS files (async)
            await self._detect_from_resources(content)

            # Generate summary finding
            if self.detected_technologies:
                await self._generate_summary_finding()

        except Exception as e:
            self._log_error(f"Technology scan failed: {e}")

        self._log_info(f"Technology scan completed. Found {len(self.detected_technologies)} technologies.")
        return self.findings

    async def _detect_from_headers(self, headers: Dict[str, str]) -> None:
        """
        Detect technologies from HTTP headers.

        Args:
            headers: HTTP response headers.
        """
        # Server header
        server = headers.get("server", "")
        if server:
            self._add_technology("Web Server", server)
            self._log_debug(f"Server: {server}")

            # Check for specific servers
            server_lower = server.lower()
            if "nginx" in server_lower:
                self._add_technology("Web Server", "nginx")
            elif "apache" in server_lower:
                self._add_technology("Web Server", "Apache")
            elif "iis" in server_lower:
                self._add_technology("Web Server", "IIS")
            elif "caddy" in server_lower:
                self._add_technology("Web Server", "Caddy")
            elif "cloudflare" in server_lower:
                self._add_technology("CDN", "Cloudflare")

        # X-Powered-By header
        x_powered_by = headers.get("x-powered-by", "")
        if x_powered_by:
            self._add_technology("Programming Language", x_powered_by)
            self._log_debug(f"X-Powered-By: {x_powered_by}")

        # X-Generator header (often used by CMS)
        x_generator = headers.get("x-generator", "")
        if x_generator:
            self._add_technology("CMS", x_generator)
            self._log_debug(f"X-Generator: {x_generator}")

        # X-AspNet-Version / X-AspNetMvc-Version
        if "x-aspnet-version" in headers:
            self._add_technology("Framework", "ASP.NET")
        if "x-aspnetmvc-version" in headers:
            self._add_technology("Framework", "ASP.NET MVC")

        # X-PHP-Version
        if "x-php-version" in headers:
            self._add_technology("Programming Language", "PHP")

        # X-Runtime (Ruby/Rails)
        if "x-runtime" in headers:
            self._add_technology("Framework", "Ruby on Rails")

        # X-Frame-Options (common in many frameworks)
        # Not a technology indicator but can suggest frameworks

        # Content-Security-Policy (can indicate framework)
        csp = headers.get("content-security-policy", "")
        if csp:
            if " 'nonce-" in csp:
                self._add_technology("Framework", "Modern Framework (CSP with nonce)")

        # Cookies
        cookies = headers.get("set-cookie", "")
        if cookies:
            cookie_lower = cookies.lower()
            if "laravel_session" in cookie_lower:
                self._add_technology("Framework", "Laravel")
            if "ci_session" in cookie_lower:
                self._add_technology("Framework", "CodeIgniter")
            if "phpsessid" in cookie_lower:
                self._add_technology("Programming Language", "PHP")
            if "jsessionid" in cookie_lower:
                self._add_technology("Programming Language", "Java")
            if "aspx" in cookie_lower or "asp.net" in cookie_lower:
                self._add_technology("Framework", "ASP.NET")
            if "wp-settings" in cookie_lower:
                self._add_technology("CMS", "WordPress")
            if "drupal" in cookie_lower:
                self._add_technology("CMS", "Drupal")
            if "joomla" in cookie_lower:
                self._add_technology("CMS", "Joomla")
            if "slim" in cookie_lower:
                self._add_technology("Framework", "Slim")

    async def _detect_from_html(self, content: str) -> None:
        """
        Detect technologies from HTML content.

        Args:
            content: HTML content.
        """
        content_lower = content.lower()

        # Meta tags
        meta_generator = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']', content, re.IGNORECASE)
        if meta_generator:
            generator = meta_generator.group(1)
            self._add_technology("CMS", generator)
            self._log_debug(f"Meta generator: {generator}")

        # CMS detection
        if "wp-content" in content_lower or "wp-includes" in content_lower:
            self._add_technology("CMS", "WordPress")
        if "drupal" in content_lower and "sites/default/files" in content_lower:
            self._add_technology("CMS", "Drupal")
        if "joomla" in content_lower and "media/system" in content_lower:
            self._add_technology("CMS", "Joomla")
        if "sitecore" in content_lower:
            self._add_technology("CMS", "Sitecore")
        if "umbraco" in content_lower:
            self._add_technology("CMS", "Umbraco")
        if "magento" in content_lower:
            self._add_technology("CMS", "Magento")
        if "prestashop" in content_lower:
            self._add_technology("CMS", "PrestaShop")
        if "shopify" in content_lower:
            self._add_technology("E-commerce", "Shopify")
        if "wix" in content_lower and "wix" in content_lower:
            self._add_technology("CMS", "Wix")
        if "squarespace" in content_lower:
            self._add_technology("CMS", "Squarespace")
        if "weebly" in content_lower:
            self._add_technology("CMS", "Weebly")
        if "webflow" in content_lower:
            self._add_technology("CMS", "Webflow")
        if "ghost" in content_lower and "ghost" in content_lower:
            self._add_technology("CMS", "Ghost")

        # JavaScript frameworks (detected by common CDN URLs or patterns)
        if "react" in content_lower and ("react" in content_lower or "reactjs" in content_lower):
            self._add_technology("Frontend Framework", "React")
        if "vue" in content_lower and ("vue.js" in content_lower or "vuejs" in content_lower):
            self._add_technology("Frontend Framework", "Vue.js")
        if "angular" in content_lower and ("angularjs" in content_lower or "angular.js" in content_lower):
            self._add_technology("Frontend Framework", "AngularJS")
        if "angular" in content_lower and "ng-version" in content_lower:
            self._add_technology("Frontend Framework", "Angular")
        if "svelte" in content_lower:
            self._add_technology("Frontend Framework", "Svelte")
        if "jquery" in content_lower:
            self._add_technology("JavaScript Library", "jQuery")
        if "bootstrap" in content_lower:
            self._add_technology("CSS Framework", "Bootstrap")
        if "tailwind" in content_lower:
            self._add_technology("CSS Framework", "Tailwind CSS")
        if "font-awesome" in content_lower or "fontawesome" in content_lower:
            self._add_technology("CSS Framework", "Font Awesome")

        # JavaScript libraries from CDN URLs
        cdn_patterns = [
            (r'cdnjs\.cloudflare\.com/ajax/libs/([^/]+)/', "JavaScript Library"),
            (r'cdn\.jsdelivr\.net/npm/([^@]+)', "JavaScript Library"),
            (r'cdn\.jsdelivr\.net/gh/([^/]+)', "JavaScript Library"),
            (r'unpkg\.com/([^/]+)', "JavaScript Library"),
            (r'cdn\.bootcdn\.net/ajax/libs/([^/]+)/', "JavaScript Library"),
            (r'cdn\.bootstrapcdn\.com/([^/]+)/', "CSS Framework"),
            (r'stackpath\.bootstrapcdn\.com/([^/]+)/', "CSS Framework"),
            (r'maxcdn\.bootstrapcdn\.com/([^/]+)/', "CSS Framework"),
            (r'cdn\.kendo\.com/', "Framework"),
            (r'cdn\.tinymce\.com/', "JavaScript Library"),
            (r'cdn\.ckeditor\.com/', "JavaScript Library"),
            (r'cdn\.datatables\.net/', "JavaScript Library"),
            (r'cdn\.plot\.ly/', "JavaScript Library"),
            (r'cdn\.chartjs\.org/', "JavaScript Library"),
            (r'cdn\.amcharts\.com/', "JavaScript Library"),
            (r'cdn\.fancybox\.net/', "JavaScript Library"),
            (r'cdn\.select2\.org/', "JavaScript Library"),
            (r'cdn\.summernote\.org/', "JavaScript Library"),
            (r'cdn\.momentjs\.com/', "JavaScript Library"),
            (r'cdn\.lodash\.com/', "JavaScript Library"),
            (r'cdn\.axios\.com/', "JavaScript Library"),
            (r'cdn\.socket\.io/', "JavaScript Library"),
        ]

        for pattern, category in cdn_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    library = match[0]
                else:
                    library = match
                self._add_technology(category, library)

        # Analytics
        analytics_patterns = [
            (r'google-analytics\.com', "Google Analytics"),
            (r'gtag\("config"', "Google Analytics 4"),
            (r'googletagmanager\.com', "Google Tag Manager"),
            (r'facebook\.com/tr', "Facebook Pixel"),
            (r'hotjar\.com', "Hotjar"),
            (r'segment\.com', "Segment"),
            (r'mixpanel\.com', "Mixpanel"),
            (r'intercom\.com', "Intercom"),
            (r'drift\.com', "Drift"),
            (r'hubspot\.com', "HubSpot"),
            (r'sentry\.io', "Sentry"),
            (r'newrelic\.com', "New Relic"),
            (r'datadog\.com', "Datadog"),
            (r'fullstory\.com', "FullStory"),
            (r'clicky\.com', "Clicky"),
            (r'crazyegg\.com', "Crazy Egg"),
            (r'optimizely\.com', "Optimizely"),
            (r'vwo\.com', "VWO"),
            (r'heatmap\.com', "Heatmap"),
            (r'clarity\.ms', "Microsoft Clarity"),
            (r'luckyorange\.com', "Lucky Orange"),
        ]

        for pattern, name in analytics_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                self._add_technology("Analytics", name)

        # Comments that reveal technologies
        comment_patterns = [
            (r'<!-- WordPress', "WordPress"),
            (r'<!-- Drupal', "Drupal"),
            (r'<!-- Joomla', "Joomla"),
            (r'<!-- Magento', "Magento"),
            (r'<!-- PrestaShop', "PrestaShop"),
            (r'<!-- Shopify', "Shopify"),
            (r'<!-- Sitecore', "Sitecore"),
            (r'<!-- Umbraco', "Umbraco"),
            (r'<!-- React', "React"),
            (r'<!-- Angular', "Angular"),
            (r'<!-- Vue', "Vue.js"),
            (r'<!-- Svelte', "Svelte"),
            (r'<!-- built with', "Custom/Unknown"),
        ]

        for pattern, name in comment_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                self._add_technology("Framework/Platform", name)

        # Specific PHP detection
        if "<?php" in content or "<?=" in content:
            self._add_technology("Programming Language", "PHP")
        if "index.php" in content_lower:
            self._add_technology("Programming Language", "PHP")

        # Python detection
        if "django" in content_lower:
            self._add_technology("Framework", "Django")
        if "flask" in content_lower:
            self._add_technology("Framework", "Flask")
        if "python" in content_lower and ("django" in content_lower or "flask" in content_lower):
            self._add_technology("Programming Language", "Python")

        # Ruby detection
        if "ruby" in content_lower and "rails" in content_lower:
            self._add_technology("Framework", "Ruby on Rails")
        if "sinatra" in content_lower:
            self._add_technology("Framework", "Sinatra")

        # Node.js detection
        if "node_modules" in content_lower:
            self._add_technology("Programming Language", "Node.js")
        if "express" in content_lower:
            self._add_technology("Framework", "Express.js")
        if "next" in content_lower and "next.js" in content_lower:
            self._add_technology("Framework", "Next.js")
        if "nuxt" in content_lower:
            self._add_technology("Framework", "Nuxt.js")
        if "gatsby" in content_lower:
            self._add_technology("Framework", "Gatsby")

    async def _detect_from_resources(self, content: str) -> None:
        """
        Detect technologies from JavaScript and CSS resources.

        Args:
            content: HTML content.
        """
        # Find JavaScript files
        js_files = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', content, re.IGNORECASE)
        for js_file in js_files:
            js_file_lower = js_file.lower()
            if "jquery" in js_file_lower:
                self._add_technology("JavaScript Library", "jQuery")
            if "bootstrap" in js_file_lower:
                self._add_technology("CSS Framework", "Bootstrap")
            if "react" in js_file_lower:
                self._add_technology("Frontend Framework", "React")
            if "vue" in js_file_lower:
                self._add_technology("Frontend Framework", "Vue.js")
            if "angular" in js_file_lower:
                self._add_technology("Frontend Framework", "Angular")
            if "svelte" in js_file_lower:
                self._add_technology("Frontend Framework", "Svelte")
            if "tailwind" in js_file_lower:
                self._add_technology("CSS Framework", "Tailwind CSS")

        # Find CSS files
        css_files = re.findall(r'href=["\']([^"\']+\.css[^"\']*)["\']', content, re.IGNORECASE)
        for css_file in css_files:
            css_file_lower = css_file.lower()
            if "bootstrap" in css_file_lower:
                self._add_technology("CSS Framework", "Bootstrap")
            if "tailwind" in css_file_lower:
                self._add_technology("CSS Framework", "Tailwind CSS")
            if "font-awesome" in css_file_lower or "fontawesome" in css_file_lower:
                self._add_technology("CSS Framework", "Font Awesome")
            if "bulma" in css_file_lower:
                self._add_technology("CSS Framework", "Bulma")
            if "materialize" in css_file_lower:
                self._add_technology("CSS Framework", "Materialize")
            if "foundation" in css_file_lower:
                self._add_technology("CSS Framework", "Foundation")
            if "semantic-ui" in css_file_lower:
                self._add_technology("CSS Framework", "Semantic UI")

    def _add_technology(self, category: str, name: str) -> None:
        """
        Add a detected technology.

        Args:
            category: Technology category.
            name: Technology name.
        """
        if category not in self.detected_technologies:
            self.detected_technologies[category] = []

        # Avoid duplicates
        if name not in self.detected_technologies[category]:
            self.detected_technologies[category].append(name)

    async def _generate_summary_finding(self) -> None:
        """
        Generate a summary finding with all detected technologies.
        """
        if not self.detected_technologies:
            return

        # Create a readable summary
        summary_lines = []
        for category, technologies in self.detected_technologies.items():
            if technologies:
                summary_lines.append(f"{category}: {', '.join(technologies)}")

        summary = "\n".join(summary_lines)

        finding = self._create_finding(
            severity="info",
            title="Detected Technologies",
            description=(
                "The following technologies were detected on the website:\n\n"
                f"{summary}"
            ),
            evidence=f"Categories detected: {', '.join(self.detected_technologies.keys())}",
            remediation=(
                "Review the detected technologies for known vulnerabilities and "
                "ensure they are up to date."
            ),
            confidence=0.85,
            references=[
                "https://builtwith.com/",
                "https://www.wappalyzer.com/",
            ],
            metadata={"technologies": self.detected_technologies},
        )
        self._add_finding(finding)

    def get_detected_technologies(self) -> Dict[str, List[str]]:
        """
        Get the detected technologies.

        Returns:
            Dict[str, List[str]]: Detected technologies by category.
        """
        return self.detected_technologies
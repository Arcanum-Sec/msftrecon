#!/usr/bin/env python3

"""
Python script to enumerate valid Microsoft 365 domains, retrieve tenant name, and check for an MDI instance.
Based on: https://github.com/thalpius/Microsoft-Defender-for-Identity-Check-Instance.
Usage: ./msftrecon.py -d <domain>
"""

import argparse
import dns.resolver
import xml.etree.ElementTree as ET
from urllib.request import urlopen, Request
import json
import socket
from typing import Dict, List, Optional, Any
import re
from urllib.error import HTTPError, URLError

class AzureRecon:
    def __init__(self, domain: str):
        self.domain = domain
        self.results: Dict = {}
        self.domain_prefix = domain.split('.')[0]

    def get_federation_info(self) -> Optional[Dict]:
        """Get Federation information for the domain"""
        try:
            url = f"https://login.microsoftonline.com/getuserrealm.srf?login=user@{self.domain}&json=1"
            request = Request(url, headers={"User-agent": "Mozilla/5.0"})
            with urlopen(request) as response:
                data = json.loads(response.read().decode())
                return data
        except Exception:
            return None

    def get_azure_ad_config(self) -> Optional[Dict]:
        """Get Azure AD OpenID configuration"""
        try:
            url = f"https://login.microsoftonline.com/{self.domain}/v2.0/.well-known/openid-configuration"
            request = Request(url, headers={"User-agent": "Mozilla/5.0"})
            with urlopen(request) as response:
                data = response.read().decode()

                try:
                    return json.loads(data)
                except json.JSONDecodeError:
                    print("ERROR: Response is not valid JSON, returning empty config.")
                    return {}
                
            debug = False  # Set to True if you want to see errors

        except HTTPError as e:
            if debug:
                print(f"ERROR: HTTP error {e.code} when accessing {url}")
        except URLError as e:
            if debug:
                print(f"ERROR: URL error {e.reason} when accessing {url}")
        except Exception as e:
            if debug:
                print(f"ERROR: Unexpected exception: {e}")
                

    def check_sharepoint(self) -> bool:
        """Check if Sharepoint is accessible"""
        try:
            sharepoint_url = f"https://{self.domain.split('.')[0]}.sharepoint.com"
            request = Request(sharepoint_url, headers={"User-agent": "Mozilla/5.0"})
            try:
                urlopen(request)
                return True
            except Exception as e:
                # If we get a 401/403, SharePoint exists but requires auth
                if hasattr(e, 'code') and e.code in [401, 403]:
                    return True
                return False
        except Exception:
            return False

    def get_mx_records(self) -> List[str]:
        """Get MX records for the domain"""
        try:
            mx_records = dns.resolver.resolve(self.domain, 'MX')
            return [str(x.exchange).rstrip('.') for x in mx_records]
        except Exception:
            return []

    def get_txt_records(self) -> List[str]:
        """Get TXT records for the domain"""
        try:
            txt_records = dns.resolver.resolve(self.domain, 'TXT')
            return [str(x).strip('"') for x in txt_records]
        except Exception:
            return []

    def get_autodiscover_endpoint(self) -> Optional[str]:
        """Check Autodiscover CNAME"""
        try:
            autodiscover = f"autodiscover.{self.domain}"
            return socket.gethostbyname(autodiscover)
        except Exception:
            return None

    def check_app_services(self) -> Dict:
        """Check for Azure App Services"""
        results = {}
        
        # Only check tenant-specific app service
        tenant_base = self.domain.split('.')[0]
        app_service_url = f"https://{tenant_base}.azurewebsites.net"
        
        try:
            request = Request(app_service_url, headers={"User-agent": "Mozilla/5.0"})
            try:
                urlopen(request)
                results[app_service_url] = "accessible"
            except Exception as e:
                if hasattr(e, 'code') and e.code in [401, 403]:
                    results[app_service_url] = "auth_required"
                else:
                    results[app_service_url] = "not_found"
        except Exception:
            results[app_service_url] = "not_found"
            
        return results

    def check_teams_presence(self) -> Dict[str, bool]:
        """Check for Teams and Skype for Business presence"""
        results = {"teams": False, "skype": False}
        
        # Check Teams
        try:
            lyncdiscover = f"lyncdiscover.{self.domain}"
            dns.resolver.resolve(lyncdiscover, 'CNAME')
            results["teams"] = True
        except Exception:
            pass

        # Check Skype for Business
        try:
            sip = f"sip.{self.domain}"
            dns.resolver.resolve(sip, 'CNAME')
            results["skype"] = True
        except Exception:
            pass

        return results

    def check_storage_accounts(self) -> List[Dict]:
        """Check for Azure Storage Accounts"""
        common_prefixes = ['storage', 'blob', 'data', self.domain_prefix]
        results = []
        
        for prefix in common_prefixes:
            try:
                urls = [
                    f"https://{prefix}.blob.core.windows.net",
                    f"https://{prefix}{self.domain_prefix}.blob.core.windows.net",
                    f"https://{self.domain_prefix}{prefix}.blob.core.windows.net"
                ]
                for url in urls:
                    try:
                        request = Request(url, headers={"User-agent": "Mozilla/5.0"})
                        try:
                            urlopen(request)
                            results.append({"url": url, "status": "accessible"})
                        except Exception as e:
                            if hasattr(e, 'code') and e.code in [401, 403]:
                                results.append({"url": url, "status": "auth_required"})
                    except Exception:
                        continue
            except Exception:
                continue
        return results

    def check_power_apps(self) -> List[str]:
        """Check for Power Apps portals"""
        try:
            urls = [
                f"https://{self.domain_prefix}.powerappsportals.com",
                f"https://{self.domain_prefix}.portal.powerapps.com"
            ]
            results = []
            for url in urls:
                try:
                    request = Request(url, headers={"User-agent": "Mozilla/5.0"})
                    try:
                        urlopen(request)
                        results.append(url)
                    except Exception as e:
                        if hasattr(e, 'code') and e.code in [401, 403]:
                            results.append(url)
                except Exception:
                    continue
            return results
        except Exception:
            return []

    def check_azure_cdn(self) -> List[str]:
        """Check for Azure CDN endpoints"""
        try:
            endpoints = [
                f"{self.domain_prefix}.azureedge.net",
                f"{self.domain_prefix}-cdn.azureedge.net",
                f"cdn-{self.domain_prefix}.azureedge.net"
            ]
            results = []
            for endpoint in endpoints:
                try:
                    socket.gethostbyname(endpoint)
                    results.append(endpoint)
                except Exception:
                    continue
            return results
        except Exception:
            return []

    def check_tenant_branding(self, tenant_id: str) -> Dict:
        """Check tenant branding information"""
        try:
            # This endpoint returns the tenant's branding configuration
            url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize"
            request = Request(url, headers={"User-agent": "Mozilla/5.0"})
            try:
                with urlopen(request) as response:
                    return {
                        "status": "accessible",
                        "custom_branding": "custom_branding" in response.read().decode().lower()
                    }
            except Exception as e:
                if hasattr(e, 'code'):
                    return {"status": f"auth_required_{e.code}"}
                return {"status": "error"}
        except Exception:
            return {"status": "error"}

    def check_provisioning_endpoints(self, tenant_id: str) -> Dict:
        """Check various provisioning endpoints"""
        endpoints = {
            "b2b": f"https://login.microsoftonline.com/{tenant_id}/B2B/invite",
            "device_registration": f"https://enterpriseregistration.windows.net/{tenant_id}/join",
            "device_management": f"https://enrollment.manage.microsoft.com/{tenant_id}/enrollmentserver/discovery.svc"
        }
        
        results = {}
        for name, url in endpoints.items():
            try:
                request = Request(url, headers={"User-agent": "Mozilla/5.0"})
                try:
                    urlopen(request)
                    results[name] = {"status": "accessible", "url": url}
                except Exception as e:
                    if hasattr(e, 'code') and e.code in [401, 403]:
                        results[name] = {"status": "protected", "url": url}
                    else:
                        results[name] = {"status": "not_found"}
            except Exception:
                results[name] = {"status": "error"}
        return results

    def check_conditional_access(self, tenant_id: str) -> Dict:
        """Check for Conditional Access configurations"""
        url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/devicecode"
        try:
            request = Request(url, headers={"User-agent": "Mozilla/5.0"})
            try:
                urlopen(request)
                return {"status": "accessible", "url": url}
            except Exception as e:
                if hasattr(e, 'code') and e.code in [401, 403]:
                    return {"status": "protected", "url": url}
                return {"status": "not_found"}
        except Exception:
            return {"status": "error"}

    def check_saml_endpoints(self, tenant_id: str) -> Dict:
        """Check SAML endpoints configuration"""
        endpoints = {
            "login": f"https://login.microsoftonline.com/{tenant_id}/saml2",
            "federation_metadata": f"https://login.microsoftonline.com/{tenant_id}/federationmetadata/2007-06/federationmetadata.xml"
        }
        
        results = {}
        for name, url in endpoints.items():
            try:
                request = Request(url, headers={"User-agent": "Mozilla/5.0"})
                try:
                    urlopen(request)
                    results[name] = {"status": "accessible", "url": url}
                except Exception as e:
                    if hasattr(e, 'code') and e.code in [401, 403]:
                        results[name] = {"status": "protected", "url": url}
                    else:
                        results[name] = {"status": "not_found"}
            except Exception:
                results[name] = {"status": "error"}
        return results

    def check_legacy_auth(self, tenant_id: str) -> Dict:
        """Check if legacy authentication endpoints are enabled"""
        endpoints = {
            "exchange_legacy": f"https://outlook.office365.com/EWS/Exchange.asmx/{tenant_id}",
            "activesync": f"https://outlook.office365.com/Microsoft-Server-ActiveSync/{tenant_id}"
        }
        
        results = {}
        for name, url in endpoints.items():
            try:
                request = Request(url, headers={"User-agent": "Mozilla/5.0"})
                try:
                    urlopen(request)
                    results[name] = {"status": "accessible", "url": url}
                except Exception as e:
                    if hasattr(e, 'code') and e.code in [401, 403]:
                        results[name] = {"status": "enabled", "url": url}
                    else:
                        results[name] = {"status": "disabled"}
            except Exception:
                results[name] = {"status": "error"}
        return results

    def check_azure_services(self, tenant_id: str) -> Dict:
        """Check various Azure services endpoints"""
        services = {
            "key_vault": f"https://{self.domain_prefix}.vault.azure.net",
            "functions": f"https://{self.domain_prefix}.azurewebsites.net/api",
            "static_web": f"https://{self.domain_prefix}.z13.web.core.windows.net",
            "container_registry": f"https://{self.domain_prefix}.azurecr.io",
            "cognitive_services": f"https://{self.domain_prefix}.cognitiveservices.azure.com"
        }
        
        results = {}
        for name, url in services.items():
            try:
                request = Request(url, headers={"User-agent": "Mozilla/5.0"})
                try:
                    urlopen(request)
                    results[name] = {"status": "accessible", "url": url}
                except Exception as e:
                    if hasattr(e, 'code') and e.code in [401, 403]:
                        results[name] = {"status": "protected", "url": url}
                    else:
                        results[name] = {"status": "not_found"}
            except Exception:
                results[name] = {"status": "error"}
        return results

    def check_b2c_configuration(self, domain: str) -> Dict[str, Any]:
        """Check for Azure B2C configuration and endpoints"""
        results = {
            "standard_endpoint": {"status": "not_found", "details": None},
            "custom_domain": {"status": "not_found", "details": None}
        }
        
        # Check standard B2C tenant endpoint
        standard_url = f"https://{domain}.b2clogin.com"
        try:
            response = urlopen(Request(standard_url, headers={"User-agent": "Mozilla/5.0"}))
            if response.status == 200:
                results["standard_endpoint"]["status"] = "found"
                results["standard_endpoint"]["details"] = "B2C tenant endpoint accessible"
                results["standard_endpoint"]["url"] = standard_url
        except HTTPError as e:
            if e.code == 404:
                results["standard_endpoint"]["status"] = "not_found"
                results["standard_endpoint"]["details"] = "No B2C tenant configured"
            else:
                results["standard_endpoint"]["status"] = "error"
                results["standard_endpoint"]["details"] = f"HTTP {e.code}"
        except URLError as e:
            results["standard_endpoint"]["status"] = "error"
            results["standard_endpoint"]["details"] = "Connection failed"
        except Exception as e:
            results["standard_endpoint"]["status"] = "error"
            results["standard_endpoint"]["details"] = str(e)

        # Check for custom domain B2C login
        try:
            custom_url = f"https://login.{domain}"
            response = urlopen(Request(custom_url, headers={"User-agent": "Mozilla/5.0"}))
            content = response.read().decode().lower()
            
            # Look for B2C indicators in response
            b2c_indicators = ["b2c", "azure ad b2c", "microsoftonline", "login.microsoftonline"]
            if any(indicator in content for indicator in b2c_indicators):
                results["custom_domain"]["status"] = "found"
                results["custom_domain"]["details"] = "Custom B2C login domain detected"
                results["custom_domain"]["url"] = custom_url
            else:
                results["custom_domain"]["status"] = "not_b2c"
                results["custom_domain"]["details"] = "Login page found but not B2C"
        except HTTPError as e:
            if e.code == 404:
                results["custom_domain"]["status"] = "not_found"
                results["custom_domain"]["details"] = "No custom login domain"
            else:
                results["custom_domain"]["status"] = "error"
                results["custom_domain"]["details"] = f"HTTP {e.code}"
        except URLError as e:
            results["custom_domain"]["status"] = "error"
            results["custom_domain"]["details"] = "Connection failed"
        except Exception as e:
            results["custom_domain"]["status"] = "error"
            results["custom_domain"]["details"] = str(e)

        return results

    def check_aad_connect_status(self) -> Dict[str, str]:
        """Check Azure AD Connect configuration using getuserrealm endpoint"""
        results = {}
        
        # Create a test email using the domain
        test_email = f"nonexistent@{self.domain}"
        url = f"https://login.microsoftonline.com/getuserrealm.srf?login={test_email}"
        
        try:
            response = urlopen(Request(url, headers={"User-agent": "Mozilla/5.0"}))
            if response.status == 200:
                data = json.loads(response.read().decode())
                results["name_space_type"] = data.get("NameSpaceType", "Unknown")
                results["federation_protocol"] = data.get("FederationProtocol", "Unknown")
                results["domain_type"] = data.get("DomainType", "Unknown")
                results["federation_brand_name"] = data.get("FederationBrandName", "Unknown")
                results["cloud_instance"] = data.get("CloudInstanceName", "Unknown")
                
                # Check if hybrid identity is configured
                if "DomainType" in data and data["DomainType"] == "Federated":
                    results["hybrid_config"] = "Federated (Hybrid Identity)"
                elif "DomainType" in data and data["DomainType"] == "Managed":
                    results["hybrid_config"] = "Managed (Cloud Only)"
                else:
                    results["hybrid_config"] = "Unknown"
                    
                # Try to get authentication methods
                if "AuthURL" in data:
                    results["auth_url"] = data["AuthURL"]
                if "FederationGlobalVersion" in data:
                    results["federation_version"] = data["FederationGlobalVersion"]
                    
        except Exception as e:
            results["error"] = str(e)
            
        return results

    def check_aad_applications(self, tenant_id: str = None) -> Dict[str, Any]:
        """Check for exposed Azure AD applications and OAuth configurations"""
        results = {
            "enterprise_apps": {},
            "public_apps": {},
            "oauth_permissions": [],
            "service_principals": [],
            "multi_tenant_apps": [],
            "permission_grants": [],
            "insights": [],
            "endpoints": {}  # Store accessible endpoints
        }
        
        # If no tenant_id provided, try to get it from the domain
        if not tenant_id:
            try:
                openid_url = f"https://login.microsoftonline.com/{self.domain}/v2.0/.well-known/openid-configuration"
                response = urlopen(Request(openid_url, headers={"User-agent": "Mozilla/5.0"}))
                if response.status == 200:
                    data = json.loads(response.read().decode())
                    if "token_endpoint" in data:
                        tenant_id = data["token_endpoint"].split("/")[3]
                        results["endpoints"]["openid_config"] = openid_url
            except Exception:
                pass

        if not tenant_id:
            results["error"] = "No tenant ID available"
            return results

        # Check enterprise applications endpoint
        enterprise_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize"
        try:
            response = urlopen(Request(enterprise_url, headers={"User-agent": "Mozilla/5.0"}))
            if response.status == 200:
                results["endpoints"]["enterprise_apps"] = enterprise_url
                content = response.read().decode()
                # Look for application IDs
                app_ids = re.findall(r'client_id=([0-9a-f-]{36})', content)
                if app_ids:
                    results["enterprise_apps"]["exposed_apps"] = app_ids
                    results["insights"].append("Found exposed enterprise application IDs - Potential OAuth abuse targets")
                    
                    # Check each app for multi-tenant configuration
                    for app_id in app_ids:
                        try:
                            app_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize?client_id={app_id}&response_type=id_token"
                            app_response = urlopen(Request(app_url, headers={"User-agent": "Mozilla/5.0"}))
                            if app_response.status == 200:
                                app_content = app_response.read().decode()
                                if "common" in app_content or "organizations" in app_content:
                                    results["multi_tenant_apps"].append(app_id)
                                    results["insights"].append(f"Multi-tenant app found: {app_id} - Potential for lateral movement")
                        except Exception:
                            continue
        except Exception as e:
            results["enterprise_apps"]["error"] = str(e)

        # Check public applications and admin consent
        public_url = f"https://login.microsoftonline.com/{tenant_id}/adminconsent"
        try:
            response = urlopen(Request(public_url, headers={"User-agent": "Mozilla/5.0"}))
            if response.status == 200:
                results["public_apps"]["status"] = "accessible"
                results["endpoints"]["admin_consent"] = public_url
                results["insights"].append("Admin consent endpoint is accessible - Check for consent phishing opportunities")
            elif response.status == 401:
                results["public_apps"]["status"] = "auth_required"
        except Exception as e:
            results["public_apps"]["error"] = str(e)

        # Check service principals
        try:
            sp_url = f"https://graph.windows.net/{tenant_id}/servicePrincipals?api-version=1.6"
            response = urlopen(Request(sp_url, headers={"User-agent": "Mozilla/5.0"}))
            if response.status == 200:
                content = response.read().decode()
                # Look for service principal names
                sp_names = re.findall(r'"displayName":"([^"]+)"', content)
                if sp_names:
                    results["service_principals"] = sp_names
                    results["insights"].append("Service principal names exposed - Review for sensitive application names")
        except Exception:
            pass

        # Check OAuth permissions and grants
        try:
            manifest_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize?client_id=common&response_type=id_token&scope=openid profile"
            response = urlopen(Request(manifest_url, headers={"User-agent": "Mozilla/5.0"}))
            if response.status == 200:
                content = response.read().decode()
                # Look for OAuth scopes and permissions
                scopes = re.findall(r'scope="([^"]+)"', content)
                if scopes:
                    results["oauth_permissions"] = scopes
                    for scope in scopes:
                        if any(p in scope.lower() for p in ["mail", "files", "directory", "user_impersonation", "full"]):
                            results["permission_grants"].append(scope)
                            results["insights"].append(f"High-privilege OAuth scope found: {scope}")
                    
                    if results["permission_grants"]:
                        results["insights"].append("High-privilege OAuth scopes detected - Review for potential abuse vectors")
        except Exception as e:
            results["oauth_permissions_error"] = str(e)

        return results

    def check_mdi_instance(self) -> Dict[str, Any]:
        """Check for Microsoft Defender for Identity instance"""
        results = {
            "detected": False,
            "details": None,
            "redteam_implications": []
        }
        
        try:
            # Check for MDI sensor endpoint
            mdi_url = f"https://sensor.atp.azure.com/test/{self.domain}"
            response = urlopen(Request(mdi_url, headers={"User-agent": "Mozilla/5.0"}))
            if response.status == 200:
                results["detected"] = True
                results["details"] = "MDI instance active"
                results["redteam_implications"] = [
                    "MDI monitors AD authentication patterns and will detect suspicious Kerberos activity (Golden/Silver tickets, overpass-the-hash)",
                    "Lateral movement techniques like remote execution and NTLM relay attacks are monitored and alerted on",
                    "Consider AMSI bypass for post-exploitation tools and use of legitimate admin tools to blend in"
                ]
        except Exception:
            pass
            
        return results

    def run_all_checks(self) -> Dict:
        """Run all reconnaissance checks"""
        # Get federation info
        fed_info = self.get_federation_info()
        results = {
            "federation_info": {
                "name_space_type": fed_info.get("NameSpaceType") if fed_info else None,
                "federation_brand_name": fed_info.get("FederationBrandName") if fed_info else None,
                "cloud_instance": fed_info.get("CloudInstanceName") if fed_info else None
            },
            "azure_ad_config": self.get_azure_ad_config(),
            "aad_connect": self.check_aad_connect_status(),
            "aad_applications": self.check_aad_applications(),
            "m365_services": {
                "sharepoint": self.check_sharepoint(),
                "mx_records": self.get_mx_records(),
                "txt_records": self.get_txt_records(),
                "autodiscover": self.get_autodiscover_endpoint()
            },
            "azure_services": {
                "app_services": self.check_app_services(),
                "storage_accounts": self.check_storage_accounts(),
                "power_apps": self.check_power_apps(),
                "cdn_endpoints": self.check_azure_cdn(),
                "b2c_configuration": self.check_b2c_configuration(self.domain)
            },
            "communication_services": self.check_teams_presence(),
            "mdi_instance": self.check_mdi_instance()
        }

        # Determine if using Microsoft 365
        uses_m365 = any([
            any("outlook.com" in mx for mx in results["m365_services"]["mx_records"]),
            any("protection.outlook.com" in txt for txt in results["m365_services"]["txt_records"]),
            results["m365_services"]["sharepoint"]
        ])
        results["uses_microsoft_365"] = uses_m365

        # Get tenant ID first as we need it for other checks
        tenant_id = None
        if "tenant_id" in results:
            tenant_id = results["tenant_id"]
        
        if tenant_id:
            # Additional Azure/M365 checks that require tenant ID
            results["tenant_config"] = {
                "branding": self.check_tenant_branding(tenant_id),
                "provisioning": self.check_provisioning_endpoints(tenant_id),
                "conditional_access": self.check_conditional_access(tenant_id),
                "legacy_auth": self.check_legacy_auth(tenant_id),
                "azure_services": self.check_azure_services(tenant_id)
            }

        return results

def print_recon_results(results: Dict, json_output: bool = False) -> None:
    """Print reconnaissance results in human-readable or JSON format"""
    if json_output:
        print(json.dumps(results, indent=2))
        return
    
    azure_config = results.get("azure_ad_config", {})  
    
    # Safely get tenant_region_scope, defaulting to "Unknown" if missing
    tenant_region_scope = azure_config.get("tenant_region_scope", "Unknown")

    print(f"Tenant Region Scope: {tenant_region_scope}")


    print("\n[+] Target Organization:")
    if results.get("tenant"):
        print(f"Tenant Name: {results['tenant']}")
    if results.get("tenant_id"):
        print(f"Tenant ID: {results['tenant_id']}")
    
    print("\n[+] Federation Information:")
    if results["federation_info"]["name_space_type"]:
        print(f"Namespace Type: {results['federation_info']['name_space_type']}")
    if results["federation_info"]["federation_brand_name"]:
        print(f"Brand Name: {results['federation_info']['federation_brand_name']}")
    if results["federation_info"]["cloud_instance"]:
        print(f"Cloud Instance: {results['federation_info']['cloud_instance']}")

    print("\n[+] Azure AD Configuration:")
    tenant_region_scope = results.get("azure_ad_config", {}).get("tenant_region_scope", "Unknown")
    if tenant_region_scope != "Unknown":
        print(f"Tenant Region: {tenant_region_scope}")
    else:
        print("Tenant Region Scope: Unknown")

    print("\n[+] Azure AD Connect Status:")
    if "aad_connect" in results:
        if "error" not in results["aad_connect"]:
            config = results["aad_connect"].get('hybrid_config', 'Unknown')
            auth_type = results["aad_connect"].get('name_space_type', 'Unknown')
            print(f"  Identity Configuration: {config}")
            print(f"  Authentication Type: {auth_type}")
            
            # Add contextual insights based on configuration
            if auth_type.lower() == "managed":
                print("\n  [!] Identity Insights:")
                print("  * Cloud-only authentication detected - No on-premises Active Directory present")
                print("  * All authentication handled in Azure AD")
                print("  * Focus on cloud-based attack vectors (OAuth, Device Code, Password Spray)")
            elif auth_type.lower() == "federated":
                print("\n  [!] Identity Insights:")
                print("  * Hybrid identity configuration detected - On-premises AD integration")
                print("  * Authentication may be handled by on-premises ADFS")
                print("  * Consider both cloud and on-premises attack vectors")
            
            if results["aad_connect"].get("auth_url"):
                print(f"\n  Federation Auth URL: {results['aad_connect']['auth_url']}")
            if results["aad_connect"].get("federation_version"):
                print(f"  Federation Version: {results['aad_connect']['federation_version']}")
        else:
            print(f"  Error checking AAD Connect status: {results['aad_connect']['error']}")

    print("\n[+] Microsoft 365 Services:")
    print(f"SharePoint Detected: {'Yes' if results['m365_services']['sharepoint'] else 'No'}")
    
    if results["m365_services"]["mx_records"]:
        print("\nMX Records:")
        for record in results["m365_services"]["mx_records"]:
            print(f"  - {record}")
    
    if results["m365_services"]["txt_records"]:
        print("\nRelevant TXT Records:")
        for record in results["m365_services"]["txt_records"]:
            if "microsoft" in record.lower() or "spf" in record.lower():
                print(f"  - {record}")

    if results["m365_services"]["autodiscover"]:
        print(f"\nAutodiscover Endpoint: {results['m365_services']['autodiscover']}")

    print(f"\n[+] Microsoft 365 Usage: {'Confirmed' if results['uses_microsoft_365'] else 'Not Detected'}")

    print("\n[+] Azure Services:")
    
    if results["azure_services"]["app_services"]:
        print("\nAzure App Services:")
        for app, status in results["azure_services"]["app_services"].items():
            print(f"  - {app} ({status})")
    
    if results["azure_services"]["storage_accounts"]:
        print("\nAzure Storage Accounts:")
        for storage in results["azure_services"]["storage_accounts"]:
            print(f"  - {storage['url']} ({storage['status']})")
    
    if results["azure_services"]["power_apps"]:
        print("\nPower Apps Portals:")
        for portal in results["azure_services"]["power_apps"]:
            print(f"  - {portal}")
    
    if results["azure_services"]["cdn_endpoints"]:
        print("\nAzure CDN Endpoints:")
        for cdn in results["azure_services"]["cdn_endpoints"]:
            print(f"  - {cdn}")

    print("\nAzure B2C Configuration:")
    if "b2c_configuration" in results["azure_services"]:
        print("  Standard B2C Endpoint:", 
              f"{results['azure_services']['b2c_configuration']['standard_endpoint']['status']} "
              f"({results['azure_services']['b2c_configuration']['standard_endpoint']['details']})")
        if results['azure_services']['b2c_configuration']['standard_endpoint']['status'] == 'found':
            print(f"    URL: {results['azure_services']['b2c_configuration']['standard_endpoint']['url']}")
        print("  Custom Domain Login:", 
              f"{results['azure_services']['b2c_configuration']['custom_domain']['status']} "
              f"({results['azure_services']['b2c_configuration']['custom_domain']['details']})")
        if results['azure_services']['b2c_configuration']['custom_domain']['status'] == 'found':
            print(f"    URL: {results['azure_services']['b2c_configuration']['custom_domain']['url']}")

    print("\n[+] Communication Services:")
    print(f"Microsoft Teams: {'Detected' if results['communication_services']['teams'] else 'Not Detected'}")
    print(f"Skype for Business: {'Detected' if results['communication_services']['skype'] else 'Not Detected'}")

    if "domains" in results:
        print("\n[+] Domains found:")
        print(*results["domains"], sep="\n")

    if "mdi_instance" in results and results["mdi_instance"]["detected"]:
        print("\n[!] Microsoft Defender for Identity (MDI) detected!")
        print("  Red Team Implications:")
        for implication in results["mdi_instance"]["redteam_implications"]:
            print(f"  * {implication}")

    print("\n[+] Azure AD Applications:")
    if "aad_applications" in results:
        if "error" not in results["aad_applications"]:
            if "enterprise_apps" in results["aad_applications"]:
                print("\n  Enterprise Applications:")
                if "exposed_apps" in results["aad_applications"]["enterprise_apps"]:
                    print("  * Exposed Application IDs:")
                    for app_id in results["aad_applications"]["enterprise_apps"]["exposed_apps"]:
                        print(f"    - {app_id}")
                    if "endpoints" in results["aad_applications"] and "enterprise_apps" in results["aad_applications"]["endpoints"]:
                        print(f"    Endpoint: {results['aad_applications']['endpoints']['enterprise_apps']}")
                elif "error" in results["aad_applications"]["enterprise_apps"]:
                    print(f"  * Error checking enterprise apps: {results['aad_applications']['enterprise_apps']['error']}")

            if "public_apps" in results["aad_applications"]:
                print("\n  Public Applications:")
                status = results["aad_applications"]["public_apps"].get("status", "unknown")
                print(f"  * Admin Consent Endpoint: {status}")
                if status == "accessible" and "endpoints" in results["aad_applications"] and "admin_consent" in results["aad_applications"]["endpoints"]:
                    print(f"    URL: {results['aad_applications']['endpoints']['admin_consent']}")

            if "service_principals" in results["aad_applications"] and results["aad_applications"]["service_principals"]:
                print("\n  Service Principals:")
                for sp in results["aad_applications"]["service_principals"]:
                    print(f"  * {sp}")

            if "permission_grants" in results["aad_applications"] and results["aad_applications"]["permission_grants"]:
                print("\n  High-Privilege OAuth Permissions:")
                for perm in results["aad_applications"]["permission_grants"]:
                    print(f"  * {perm}")

            if "insights" in results["aad_applications"]:
                print("\n  [!] Application Security Insights:")
                for insight in results["aad_applications"]["insights"]:
                    print(f"  * {insight}")
        else:
            print(f"  Error checking AAD applications: {results['aad_applications']['error']}")

# Get domains
def get_domains(args):
    domain = args.domain
    json_out = {}

    # Run reconnaissance first
    recon = AzureRecon(domain)
    recon_results = recon.run_all_checks()
    
    if not args.json:
        print("\n[+] Running Azure/M365 Reconnaissance...")
    
    # Create a valid HTTP request
    # Example from: https://github.com/thalpius/Microsoft-Defender-for-Identity-Check-Instance.
    body = f"""<?xml version="1.0" encoding="utf-8"?>
    <soap:Envelope xmlns:exm="http://schemas.microsoft.com/exchange/services/2006/messages" 
        xmlns:ext="http://schemas.microsoft.com/exchange/services/2006/types" 
        xmlns:a="http://www.w3.org/2005/08/addressing" 
        xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" 
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
        <soap:Header>
            <a:RequestedServerVersion>Exchange2010</a:RequestedServerVersion>
            <a:MessageID>urn:uuid:6389558d-9e05-465e-ade9-aae14c4bcd10</a:MessageID>
            <a:Action soap:mustUnderstand="1">http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation</a:Action>
            <a:To soap:mustUnderstand="1">https://autodiscover.byfcxu-dom.extest.microsoft.com/autodiscover/autodiscover.svc</a:To>
            <a:ReplyTo>
            <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
            </a:ReplyTo>
        </soap:Header>
        <soap:Body>
            <GetFederationInformationRequestMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">
            <Request>
                <Domain>{domain}</Domain>
            </Request>
            </GetFederationInformationRequestMessage>
        </soap:Body>
    </soap:Envelope>"""

    # Including HTTP headers
    headers = {
        "Content-type": "text/xml; charset=utf-8",
        "User-agent": "AutodiscoverClient"
    }

    url = "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc"
    if args.gov: 
        url = "https://autodiscover-s.office365.us/autodiscover/autodiscover.svc"
    elif args.cn:
        url = "https://autodiscover-s.partner.outlook.cn/autodiscover/autodiscover.svc"

    # Perform HTTP request
    try:
        httprequest = Request(
            url, headers=headers, data=body.encode())

        with urlopen(httprequest) as response:
            response = response.read().decode()
    except Exception:
        if args.json: 
            print(json.dumps({"error":"Unable to execute request. Wrong domain"},indent=1))
        else:
            print("[-] Unable to execute request. Wrong domain?")
        exit()
    #print(response)
    # Parse XML response
    domains = []

    tree = ET.fromstring(response)
    for elem in tree.iter():
        if elem.tag == "{http://schemas.microsoft.com/exchange/2010/Autodiscover}Domain":
            domains.append(elem.text)

    # Get tenant name
    tenant = ""
    for domain in domains:
        if "onmicrosoft.com" in domain:
            tenant = domain.split(".")[0]
    
    # Get tenant ID
    tenant_id = get_tenant_id(domain)
    print("DEBUG: recon_results before calling print_recon_results:")
    print(json.dumps(recon_results, indent=4))
    # Store results
    recon_results["domains"] = domains
    recon_results["tenant"] = tenant
    recon_results["tenant_id"] = tenant_id
    
    if not args.json:
        print_recon_results(recon_results)
    else:
        print(json.dumps(recon_results, indent=2))


# Get tenant ID
def get_tenant_id(domain):
    try:
        url = f"https://login.microsoftonline.com/{domain}/v2.0/.well-known/openid-configuration"
        request = Request(url, headers={"User-agent": "Mozilla/5.0"})
        with urlopen(request) as response:
            data = json.loads(response.read().decode())
            # Extract tenant ID from the token endpoint instead of issuer
            token_endpoint = data.get("token_endpoint", "")
            tenant_id = token_endpoint.split("/")[3] if token_endpoint else None
            return tenant_id if tenant_id != "v2.0" else None
    except Exception:
        return None


# Identify MDI usage
def check_mdi(tenant):

    tenant += ".atp.azure.com"

    # Check if MDI instance exists
    try:
        dns.resolver.resolve(tenant)
        return True
    except Exception:
        return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Enumerates valid Microsoft 365 domains, retrieves tenant name, and checks for MDI instance")
    parser.add_argument(
        "-d", "--domain", help="input domain name, example format: example.com", required=True)
    parser.add_argument(
        "-j", "--json", action="store_true", help="output in JSON format", required=False)
    parser.add_argument(
        "--gov", action="store_true", help="query government tenancy", required=False)
    parser.add_argument(
        "--cn", action="store_true", help="query chinese tenancy", required=False)
    args = parser.parse_args()
    get_domains(args)

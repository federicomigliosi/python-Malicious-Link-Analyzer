import base64
import requests
import json


class URL:

    def __init__(self,url):
        self.url = url
        self.virus_total_phishing_reports_count = None
        self.google_threat_type = None


    def check_url_virus_total(self, virus_total_api_key):
        url_to_check = self.url

        #   1: Converts the url_to_check string from its Unicode representation to a UTF-8 encoded byte string.
        #   2: Encodes the UTF-8 byte string into its Base64 representation using the URL and filename-safe alphabet
        encoded_url_to_check = base64.urlsafe_b64encode(url_to_check.encode('utf-8')).decode().rstrip("=")

        api_url = "https://www.virustotal.com/api/v3/urls/" + encoded_url_to_check

        headers = {"x-apikey": virus_total_api_key}

        try:

            response = requests.get(api_url,headers=headers)
            response.raise_for_status()

            self.virus_total_phishing_reports_count = 0

            JSONresponse = response.json()

            analysis_results = JSONresponse['data']['attributes']['last_analysis_results']

            # Iterate through each entry in 'last_analysis_results'
            for result_entry in analysis_results.values():
            # Check if the 'result' key exists and its value is 'phishing'
                if 'result' in result_entry and result_entry['result'] == 'phishing':
                    # Increment the counter for phishing occurrences
                    self.virus_total_phishing_reports_count += 1
        
        #Catch request specific exceptions
        except requests.RequestException:
            pass
        #Catch all exceptions
        except Exception:
            pass


    def check_url_google_safe_browsing(self, google_safe_browsing_api_key):

        url_to_check = self.url

        api_url='https://safebrowsing.googleapis.com/v4/threatMatches:find'

        data = {
                "client": {
                    "clientId": "test",
                    "clientVersion": "1"
                },
                "threatInfo": {
                    "threatTypes":
                        [
                            "MALWARE",
                            "SOCIAL_ENGINEERING",
                            "THREAT_TYPE_UNSPECIFIED",
                            "UNWANTED_SOFTWARE",
                            "POTENTIALLY_HARMFUL_APPLICATION"
                        ],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{'url': url_to_check}]
                }
            }

        headers = {'Content-type': 'application/json'}

        params={'key': google_safe_browsing_api_key}

        try: 
            response = requests.post(api_url,data=json.dumps(data),params=params,headers=headers)
            response.raise_for_status()

            JSONresponse = response.json()
            
            # If the link is considered unsafe 
            if JSONresponse != {}:
                self.google_threat_type = JSONresponse["matches"][0]["threatType"]
                
            # If the link is considered safe 
            else:
                self.google_threat_type = "NO_THREAT"

        #Catch request specific exceptions
        except requests.RequestException:
            pass
        #Catch all exceptions
        except Exception:
            pass

from tabulate import tabulate
from url import URL

def print_results(arg):
    if isinstance(arg, URL):
        results = [[arg.url, arg.virus_total_phishing_reports_count, arg.google_threat_type]]
        print(tabulate(results, headers=["","Number of phishing reports from VirusTotal","Threat type from Google SB"]))
        print("")
    elif isinstance(arg, list) and all(isinstance(url, URL) for url in arg):
        results = [[url.url, url.virus_total_phishing_reports_count, url.google_threat_type] for url in arg]
        print(tabulate(results, headers=["","Number of phishing reports from VirusTotal","Threat type from Google SB"]))
        print("")
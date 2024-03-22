import argparse
from dotenv import load_dotenv

from url import URL
from get_API_keys import get_keys 
from print_results import *

parser = argparse.ArgumentParser(prog="Malicious Link Analyzer", 
                                    description="A Python command line tool that leverages the VirusTotal API and Google Safe Browsing API to analyze links for potential malicious content.", 
                                    formatter_class=argparse.ArgumentDefaultsHelpFormatter)
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('--link',help="desc")
group.add_argument('--file',help="desc")
parser.add_argument("-v", help="desc")
parser.add_argument("-g", help="desc")
args = parser.parse_args()

#Loading API keys
VIRUS_TOTAL_API_KEY, GOOGLE_SAFE_BROWSING_API_KEY = get_keys(args)

#If a link is provided as input
if args.link is not None:
    url_object = URL(args.link)
    url_object.check_url_virus_total(VIRUS_TOTAL_API_KEY)
    url_object.check_url_google_safe_browsing(GOOGLE_SAFE_BROWSING_API_KEY)
    print_results(url_object)
#If a file path is provided as input
elif args.file is not None:
    with open(args.file, 'rt') as file:
        url_object_list = [URL(line.strip()) for line in file.readlines()]
        for url_object in url_object_list:
            url_object.check_url_virus_total(VIRUS_TOTAL_API_KEY)
            url_object.check_url_google_safe_browsing(GOOGLE_SAFE_BROWSING_API_KEY)
        print_results(url_object_list)
        


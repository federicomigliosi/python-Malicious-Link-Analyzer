import os
from dotenv import load_dotenv

def get_keys(args):

    load_dotenv()

    #   Load VIRUS_TOTAL_API_KEY
    if args.v is None:
        VIRUS_TOTAL_API_KEY = os.getenv("VIRUS_TOTAL_API_KEY")
    elif args.v is not None:
        VIRUS_TOTAL_API_KEY = args.v

    # Loading GOOGLE_SAFE_BROWSING_API_KEY
    if args.g is None:
        GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
    elif args.g is not None:
        GOOGLE_SAFE_BROWSING_API_KEY = args.g

    return VIRUS_TOTAL_API_KEY, GOOGLE_SAFE_BROWSING_API_KEY
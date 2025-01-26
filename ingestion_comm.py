import json
import google.auth
from google.auth.transport import requests
from google.oauth2 import service_account

# Load configuration file
def load_config(filename):
    config = {}
    with open(filename, 'r') as file:
        for line in file:
            line = line.strip()
            if line and '=' in line:
                key, value = line.split('=', 1)
                config[key.strip()] = value.strip()
    return config
config = load_config('config.conf')

# Load costumer id and credentials
customer_id = config['CUSTOMER_ID']
ing_service_account_file = config['ING_SERVICE_ACCOUNT_FILE']

# Regional endpoint for API call - Turin
INGESTION_API = "https://europe-west12-malachiteingestion-pa.googleapis.com"

# Permissions API ingestion Chronicle
SCOPES = ['https://www.googleapis.com/auth/malachite-ingestion']

# Create a credential using an Ingestion Service Account Credential and Google Security Operations API
credentials = service_account.Credentials.from_service_account_file(ing_service_account_file, scopes=SCOPES)

# Build an authorized HTTP session
http_session = requests.AuthorizedSession(credentials)

# Complete endpoint
url = f"{INGESTION_API}/v2/udmevents:batchCreate"

# request body
body = {
    "customerId": customer_id,
    "events": json.loads(json_events),
}
response = http_session.request("POST", 
                                url, 
                                json=body)
import json

# Gestione autenticazione e richieste HTTP
from google.auth.transport import requests
from google.oauth2 import service_account

# Accesso API ingestion Chronicle
SCOPES = ['https://www.googleapis.com/auth/malachite-ingestion']

# The apikeys-demo.json file contains the customer's OAuth 2 credentials.
# Credenziali
ING_SERVICE_ACCOUNT_FILE = '/customer-keys/apikeys.json'
CUSTOMER_ID="01234567-89ab-cdef-0123-456789abcdef" #fittizio

# Create a credential using an Ingestion Service Account Credential and Google Security Operations API
# Scope.
credentials = service_account.Credentials.from_service_account_file(ING_SERVICE_ACCOUNT_FILE, scopes=SCOPES)

# Build a requests Session Object to make authorized OAuth requests.
http_session = requests.AuthorizedSession(credentials)

# UDM Event example (for US region)
# url = 'https://malachiteingestion-pa.googleapis.com/v2/udmevents:batchCreate'
# Specifica l'URL dell'endpoint dell'API di ingestione per la creazione di eventi UDM (Unified Data Model)
# regional endpoint for your API call
url = 'https://europe-west12-malachiteingestion-pa.googleapis.com/v2/udmevents:batchCreate' # Turin

# request body
body = {
    "customerId": CUSTOMER_ID,
    "events": json.loads(json_events),
}
response = http_session.request("POST", 
                                url, 
                                json=body)

# For more complete examples, see:
# https://github.com/chronicle/api-samples-python/blob/master/ingestion/create_entities.py
# https://github.com/chronicle/api-samples-python/blob/master/ingestion/create_udm_events.py
# https://github.com/chronicle/api-samples-python/blob/master/ingestion/create_unstructured_log_entries.py
import requests
import string
import random
import logging
import json
import pandas as pd
import tkinter as tk
from tkinter import filedialog

# Function to prompt user for file selection
def select_file():
    root = tk.Tk()
    root.withdraw()
    file_path = filedialog.askopenfilename(title="Select Excel File", filetypes=[("Excel files", "*.xlsx")])
    return file_path

# Load user data from Excel file
def load_users_from_excel():
    file_path = select_file()
    if not file_path:
        print("No file selected. Exiting.")
        return []
    df = pd.read_excel(file_path)
    users = []
    for _, row in df.iterrows():
        username = generate_username(row["FIRSTNAME"], row["LASTNAME"])
        users.append({
            "attributes": {
                "PHONENUMBER": str(row["PHONENUMBER"]),
                "COUNTRY": row["COUNTRY"],
                "AGENTIDENTIFIER": str(row["AGENTIDENTIFIER"]),
                "USERCOUNTRY": row["USERCOUNTRY"],
                "REGION": row["REGION"],
            },
            "requiredActions": [],
            "emailVerified": False,
            "username": username,
            "email": row["EMAIL"].strip(),
            "firstName": row["FIRSTNAME"].strip(),
            "lastName": row["LASTNAME"].strip(),
            "groups": [row["GROUPS"].strip()],
            "enabled": True,
            "credentials": [{"type": "password", "value": str(row["PASSWORD"].strip()), "temporary": False}],
            "realmRoles": [row["ROLE MAPPING"].strip()]

        })
        print(f"Generated username: {username} for {row['FIRSTNAME']} {row['LASTNAME']}")
    print(f"Loaded {len(users)} users from file.")
    return users

def generate_username(first_name, last_name):
    random_suffix = ''.join(random.choices(string.digits, k=2))
    return f"{first_name.strip().lower()}.{last_name.strip().lower()}{random_suffix}".replace(" ", "")

GRANT_TYPE = "client_credentials"
CLIENT_ID = "CrmMS"
CLIENT_SECRET = "XVD8jeRjRauEt13fd8KUwMTGy0dlK4h4"
#"nUveQnxKF8r4qObqnQIRTUmETYds7grt" laivu
#"XVD8jeRjRauEt13fd8KUwMTGy0dlK4h4" dev
KEYCLOAK_SERVER_URL = "https://s4x3dvs2a9.eu-west-1.awsapprunner.com/realms/master/protocol/openid-connect/token"
#"https://s4x3dvs2a9.eu-west-1.awsapprunner.com/realms/master/protocol/openid-connect/token" dev
#"https://pwbbp42etp.eu-west-1.awsapprunner.com/realms/master/protocol/openid-connect/token" laivu
#

def get_keycloak_token():
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json"
    }
    data = {
        "grant_type": GRANT_TYPE,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET
    }
    try:
        response = requests.post(KEYCLOAK_SERVER_URL, headers=headers, data=data)
        response.raise_for_status()
        token_response = response.json()
        token = token_response.get("access_token")
        if not token:
            raise ValueError("No access token found in the response")
        print(f"Retrieved token: {token[:10]}...")
        return token
    except requests.RequestException as e:
        raise ValueError(f"Failed to retrieve Keycloak token: {e}")

def create_user(data):
    url = "https://pwbbp42etp.eu-west-1.awsapprunner.com/admin/realms/master/users"
    #"https://s4x3dvs2a9.eu-west-1.awsapprunner.com/admin/realms/master/users" dev
    #"https://pwbbp42etp.eu-west-1.awsapprunner.com/admin/realms/master/users" laivu
    token = get_keycloak_token()
    
    headers = {'Content-Type': 'application/json', 'Authorization': f'Bearer {token}'}
    
    #data['credentials'] = [{'type': 'password', 'value': 'password', 'temporary': True}]
    
    #print("Sending user data:", json.dumps(data, indent=4))
    
    response = requests.post(url, json=data, headers=headers)
    
    if response.status_code in [200, 201]:
        print(f"User {data['username']} created successfully.")
    else:
        print("Error occurred while sending data:", response.text)

# Main Execution
users = load_users_from_excel()
print(f"Loaded {len(users)} users from file.")

for user in users:
    create_user(user)
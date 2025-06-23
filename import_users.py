import requests
import string
import random
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
            "credentials": [{"type": "password", "value": str(row["PASSWORD"]).strip(), "temporary": False}],
            "realmRoles": [row["ROLE MAPPING"].strip()]
        })
        print(f"Generated username: {username} for {row['FIRSTNAME']} {row['LASTNAME']}")
    print(f"Loaded {len(users)} users from file.")
    return users

def generate_username(first_name, last_name):
    random_suffix = ''.join(random.choices(string.digits, k=2))
    return f"{first_name.strip().lower()}.{last_name.strip().lower()}{random_suffix}".replace(" ", "")

# === Keycloak Configuration ===
GRANT_TYPE = "client_credentials"
CLIENT_ID = "CrmMS"
CLIENT_SECRET = "XVD8jeRjRauEt13fd8KUwMTGy0dlK4h4"
#"nUveQnxKF8r4qObqnQIRTUmETYds7grt" laivu
#"XVD8jeRjRauEt13fd8KUwMTGy0dlK4h4" dev
KEYCLOAK_SERVER_URL = "https://s4x3dvs2a9.eu-west-1.awsapprunner.com/realms/master/protocol/openid-connect/token"
#"https://s4x3dvs2a9.eu-west-1.awsapprunner.com/realms/master/protocol/openid-connect/token" dev
#"https://pwbbp42etp.eu-west-1.awsapprunner.com/realms/master/protocol/openid-connect/token" laivu

KEYCLOAK_ADMIN_USERS_URL = "https://s4x3dvs2a9.eu-west-1.awsapprunner.com/admin/realms/master/users"
#"https://s4x3dvs2a9.eu-west-1.awsapprunner.com/admin/realms/master/users" dev
#"https://pwbbp42etp.eu-west-1.awsapprunner.com/admin/realms/master/users" laivu
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
        token = response.json().get("access_token")
        if not token:
            raise ValueError("No access token found in response")
        print(f"Retrieved token: {token[:10]}...")
        return token
    except requests.RequestException as e:
        raise ValueError(f"Failed to retrieve Keycloak token: {e}")

# def create_user(data, token):
#     headers = {
#         'Content-Type': 'application/json',
#         'Authorization': f'Bearer {token}'
#     }
#     response = requests.post(KEYCLOAK_ADMIN_USERS_URL, json=data, headers=headers)
    
#     if response.status_code in [200, 201]:
#         print(f"User {data['username']} created successfully.")
#     else:
#         print(f"Error creating {data['username']}: {response.status_code} - {response.text}")


def create_user(data, token):
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {token}'
    }

    print(f"\n==> Sending data for user: {data['username']}")
    print(json.dumps(data, indent=2))  # Print pretty JSON

    response = requests.post(KEYCLOAK_ADMIN_USERS_URL, json=data, headers=headers)
    
    if response.status_code in [200, 201]:
        print(f"✅ User {data['username']} created successfully.")
        # Extract user ID from Location header
        location = response.headers.get('Location')
        if location:
            user_id = location.rstrip('/').split('/')[-1]
            return user_id
    else:
        print(f"❌ Error creating {data['username']}: {response.status_code} - {response.text}")


# Creating realms and roles is not implemented in this script.

def assign_realm_roles(user_id, roles, token):
    url = f"https://s4x3dvs2a9.eu-west-1.awsapprunner.com/admin/realms/master/users/{user_id}/role-mappings/realm"
    #"https://s4x3dvs2a9.eu-west-1.awsapprunner.com/admin/realms/master/users" dev
    #"https://pwbbp42etp.eu-west-1.awsapprunner.com/admin/realms/master/users" laivu
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {token}'
    }

    # Fetch all available realm roles to match role names with their IDs
    roles_response = requests.get("https://s4x3dvs2a9.eu-west-1.awsapprunner.com/admin/realms/master/roles", headers=headers)
    #"https://s4x3dvs2a9.eu-west-1.awsapprunner.com/admin/realms/master/users" dev
    #"https://pwbbp42etp.eu-west-1.awsapprunner.com/admin/realms/master/users" laivu
    if roles_response.status_code != 200:
        print("⚠️ Could not retrieve realm roles.")
        return

    available_roles = roles_response.json()
    matched_roles = [role for role in available_roles if role["name"] in roles]

    if not matched_roles:
        print(f"⚠️ No matching roles found for: {roles}")
        return

    assign_response = requests.post(url, headers=headers, json=matched_roles)
    if assign_response.status_code in [204, 200]:
        print(f"✅ Assigned roles {roles} to user {user_id}")
    else:
        print(f"❌ Failed to assign roles to user {user_id}: {assign_response.status_code} - {assign_response.text}")



# === Main Execution ===
users = load_users_from_excel()
if users:
    token = get_keycloak_token()
    for user in users:
        create_user(user, token)

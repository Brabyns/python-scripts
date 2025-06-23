import requests
import string
import random
import json
import pandas as pd
import tkinter as tk
from tkinter import filedialog
import logging
from tqdm import tqdm

# === Setup Logging ===
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s',
    handlers=[
        logging.FileHandler("keycloak_import.log"),
        logging.StreamHandler()
    ]
)

# === Config ===
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
KEYCLOAK_REALM_ROLES_URL = "https://s4x3dvs2a9.eu-west-1.awsapprunner.com/admin/realms/master/roles"
#"https://s4x3dvs2a9.eu-west-1.awsapprunner.com/admin/realms/master/roles" dev
#"https://pwbbp42etp.eu-west-1.awsapprunner.com/admin/realms/master/roles" laivu


# === Excel Handling ===
def select_file():
    root = tk.Tk()
    root.withdraw()
    file_path = filedialog.askopenfilename(title="Select Excel File", filetypes=[("Excel files", "*.xlsx")])
    return file_path

def validate_excel_columns(df):
    required = {"FIRSTNAME", "LASTNAME", "EMAIL", "PASSWORD", "GROUPS", "ROLE MAPPING"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Missing required columns: {missing}")

def generate_username(first_name, last_name):
    suffix = ''.join(random.choices(string.digits, k=2))
    return f"{first_name.strip().lower()}.{last_name.strip().lower()}{suffix}".replace(" ", "")

def load_users_from_excel():
    file_path = select_file()
    if not file_path:
        logging.warning("No file selected. Exiting.")
        return []
    df = pd.read_excel(file_path)
    validate_excel_columns(df)
    users = []
    for _, row in df.iterrows():
        username = generate_username(row["FIRSTNAME"], row["LASTNAME"])
        user = {
            "attributes": {
                "PHONENUMBER": str(row.get("PHONENUMBER", "")),
                "COUNTRY": row.get("COUNTRY", ""),
                "AGENTIDENTIFIER": str(row.get("AGENTIDENTIFIER", "")),
                "USERCOUNTRY": row.get("USERCOUNTRY", ""),
                "REGION": row.get("REGION", ""),
            },
            "requiredActions": [],
            "emailVerified": False,
            "username": username,
            "email": row["EMAIL"].strip(),
            "firstName": row["FIRSTNAME"].strip(),
            "lastName": row["LASTNAME"].strip(),
            "groups": [row["GROUPS"].strip()],  
            "enabled": True,
            "credentials": [{
                "type": "password",
                "value": str(row["PASSWORD"]).strip(),
                "temporary": False
            }],
            "realmRoles": [r.strip() for r in str(row["ROLE MAPPING"]).split(",") if r.strip()]

        }
        users.append(user)
        logging.info(f"Prepared user: {username}")
    return users

# === Keycloak Token and User Creation ===
def get_keycloak_token():
    headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
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
        logging.info("Keycloak token retrieved successfully.")
        return token
    except requests.RequestException as e:
        logging.error(f"Token retrieval failed: {e}")
        return None

def create_user(user_data, token):
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {token}'
    }
    try:
        response = requests.post(KEYCLOAK_ADMIN_USERS_URL, json=user_data, headers=headers)
        if response.status_code in [201, 204]:
            logging.info(f"✅ User {user_data['username']} created.")
            location = response.headers.get('Location')
            if location:
                return location.rstrip('/').split('/')[-1]
        elif response.status_code == 409:
            logging.warning(f"User {user_data['username']} already exists.")
        else:
            logging.error(f"❌ Failed to create {user_data['username']}: {response.status_code} - {response.text}")
    except Exception as e:
        logging.error(f"Unexpected error for {user_data['username']}: {e}")
    return None

def assign_realm_roles(user_id, roles, token):
    headers = {'Content-Type': 'application/json', 'Authorization': f'Bearer {token}'}
    # Fetch all available realm roles
    roles_response = requests.get(KEYCLOAK_REALM_ROLES_URL, headers=headers)
    if roles_response.status_code != 200:
        logging.error("⚠️ Could not retrieve realm roles.")
        return
    available_roles = roles_response.json()
    matched_roles = [role for role in available_roles if role["name"] in roles]
    if not matched_roles:
        logging.warning(f"⚠️ No matching realm roles found: {roles}")
        return
    assign_url = f"{KEYCLOAK_ADMIN_USERS_URL}/{user_id}/role-mappings/realm"
    assign_response = requests.post(assign_url, headers=headers, json=matched_roles)
    if assign_response.status_code in [204, 200]:
        logging.info(f"✅ Assigned roles {roles} to user {user_id}")
    else:
        logging.error(f"❌ Failed to assign roles to user {user_id}: {assign_response.status_code} - {assign_response.text}")

# === Main Execution ===
if __name__ == "__main__":
    users = load_users_from_excel()
    if users:
        token = get_keycloak_token()
        if token:
            successes, failures = [], []
            for user in tqdm(users, desc="Creating users"):
                user_copy = user.copy()
                roles = user_copy.pop("realmRoles", [])
                user_id = create_user(user_copy, token)
                if user_id:
                    assign_realm_roles(user_id, roles, token)
                    successes.append(user)
                else:
                    failures.append(user)
            pd.DataFrame(successes).to_excel("created_users.xlsx", index=False)
            pd.DataFrame(failures).to_excel("failed_users.xlsx", index=False)
            logging.info(f"✅ Finished. {len(successes)} created, {len(failures)} failed.")

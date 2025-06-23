import requests
import pandas as pd
import logging
from tkinter import filedialog, Tk

# === Setup Logging ===
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

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
# === Select Excel File ===
def select_file():
    root = Tk()
    root.withdraw()
    return filedialog.askopenfilename(title="Select Excel File", filetypes=[("Excel files", "*.xlsx")])

# === Get Keycloak Token ===
def get_keycloak_token():
    headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
    data = {
        "grant_type": GRANT_TYPE,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET
    }
    response = requests.post(KEYCLOAK_SERVER_URL, headers=headers, data=data)
    response.raise_for_status()
    return response.json().get("access_token")

# === Get User by Username (or fallback to email) ===
def get_user_by_username_or_email(identifier, token):
    headers = {"Authorization": f"Bearer {token}"}
    
    # Search by username
    params = {"username": identifier}
    resp = requests.get(KEYCLOAK_ADMIN_USERS_URL, headers=headers, params=params)
    if resp.status_code == 200 and resp.json():
        return resp.json()[0]

    # Fallback: search by email
    params = {"email": identifier}
    resp = requests.get(KEYCLOAK_ADMIN_USERS_URL, headers=headers, params=params)
    if resp.status_code == 200 and resp.json():
        return resp.json()[0]

    return None

# === Update User ===
def update_user(user_id, updates, token):
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    url = f"{KEYCLOAK_ADMIN_USERS_URL}/{user_id}"
    resp = requests.put(url, json=updates, headers=headers)
    return resp.status_code in [204, 200]


def update_user_password(user_id, password, token):
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    url = f"{KEYCLOAK_ADMIN_USERS_URL}/{user_id}/reset-password"
    payload = {
        "type": "password",
        "value": password,
        "temporary": False
    }
    response = requests.put(url, headers=headers, json=payload)
    return response.status_code in [204, 200]


# === Main ===
def main():
    file_path = select_file()
    if not file_path:
        logging.warning("No file selected.")
        return

    df = pd.read_excel(file_path)
    token = get_keycloak_token()

    for _, row in df.iterrows():
        identifier = str(row.get("USERNAME") or row.get("EMAIL", "")).strip()
        user = get_user_by_username_or_email(identifier, token)

        if not user:
            logging.warning(f"User with identifier {identifier} not found.")
            continue

        user_id = user["id"]
        username = user.get("username", identifier)

        updates = {
            "firstName": str(row.get("FIRSTNAME", user.get("firstName", ""))).strip(),
            "lastName": str(row.get("LASTNAME", user.get("lastName", ""))).strip(),
            "attributes": {
                "PHONENUMBER": str(row.get("PHONENUMBER", user.get("attributes", {}).get("PHONENUMBER", ""))).strip(),
                "COUNTRY": str(row.get("COUNTRY", user.get("attributes", {}).get("COUNTRY", ""))).strip(),
                "AGENTIDENTIFIER": str(row.get("AGENTIDENTIFIER", user.get("attributes", {}).get("AGENTIDENTIFIER", ""))).strip(),
                "USERCOUNTRY": str(row.get("USERCOUNTRY", user.get("attributes", {}).get("USERCOUNTRY", ""))).strip(),
                "REGION": str(row.get("REGION", user.get("attributes", {}).get("REGION", ""))).strip(),
            }
        }

        # Optionally update groups
        group_value = str(row.get("GROUPS", "")).strip()
        if group_value:
            updates["groups"] = [group_value]

        # Optionally update realm roles
        role_mapping_value = str(row.get("ROLE MAPPING", "")).strip()
        if role_mapping_value:
            updates["realmRoles"] = [r.strip() for r in role_mapping_value.split(",") if r.strip()]

        # if update_user(user_id, updates, token):
        #     logging.info(f"✅ Updated user {username} successfully.")
        # else:
        #     logging.error(f"❌ Failed to update user {username}.")

        if update_user(user_id, updates, token):
            logging.info(f"✅ Updated user {username} successfully.")

            # Update password if provided
            password = str(row.get("PASSWORD", "")).strip()
            if password:
                if update_user_password(user_id, password, token):
                    logging.info(f"🔐 Password updated for {username}")
                else:
                    logging.error(f"❌ Failed to update password for {username}")
        else:
           logging.error(f"❌ Failed to update user {username}.")
    

if __name__ == "__main__":
    main()

import requests
import pandas as pd
import logging
import unicodedata
import re
import time
from tkinter import filedialog, Tk
from concurrent.futures import ThreadPoolExecutor

# === Setup Logging ===
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s %(levelname)s: %(message)s')

# === Config ===
GRANT_TYPE = "client_credentials"
CLIENT_ID = "CrmMS"
CLIENT_SECRET = "XVD8jeRjRauEt13fd8KUwMTGy0dlK4h4"
KEYCLOAK_SERVER_URL = "https://s4x3dvs2a9.eu-west-1.awsapprunner.com/realms/master/protocol/openid-connect/token"
KEYCLOAK_ADMIN_USERS_URL = "https://s4x3dvs2a9.eu-west-1.awsapprunner.com/admin/realms/master/users"

# === File Picker ===


def select_file():
    root = Tk()
    root.withdraw()
    return filedialog.askopenfilename(title="Select Excel File", filetypes=[("Excel files", "*.xlsx")])

# === Get Token ===


def get_keycloak_token():
    headers = {"Content-Type": "application/x-www-form-urlencoded",
               "Accept": "application/json"}
    data = {
        "grant_type": GRANT_TYPE,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET
    }
    response = requests.post(KEYCLOAK_SERVER_URL, headers=headers, data=data)
    response.raise_for_status()
    return response.json().get("access_token")

# === Get User ===


def get_user_by_username_or_email(identifier, token):
    headers = {"Authorization": f"Bearer {token}"}
    for key in ["username", "email"]:
        params = {key: identifier}
        resp = requests.get(KEYCLOAK_ADMIN_USERS_URL,
                            headers=headers, params=params)
        if resp.status_code == 200 and resp.json():
            return resp.json()[0]
    return None

# === Update User Basic Info ===


def update_user(user_id, updates, token):
    headers = {"Authorization": f"Bearer {token}",
               "Content-Type": "application/json"}
    url = f"{KEYCLOAK_ADMIN_USERS_URL}/{user_id}"
    resp = requests.put(url, json=updates, headers=headers)
    return resp.status_code in [204, 200]

# === Update Password ===


def update_user_password(user_id, password, token):
    headers = {"Authorization": f"Bearer {token}",
               "Content-Type": "application/json"}
    url = f"{KEYCLOAK_ADMIN_USERS_URL}/{user_id}/reset-password"
    payload = {
        "type": "password",
        "value": password,
        "temporary": False
    }
    response = requests.put(url, headers=headers, json=payload)
    return response.status_code in [204, 200]

# === Group Utilities ===


def normalize_path(text):
    if not text:
        return ""
    text = unicodedata.normalize("NFKC", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip().lower()


def fetch_all_groups(token):
    headers = {"Authorization": f"Bearer {token}"}
    realm_url = KEYCLOAK_ADMIN_USERS_URL.rsplit("/users", 1)[0]

    def recurse_groups(group_id=None, path_prefix="", depth=0, max_depth=6):
        if depth > max_depth:
            return []
        url = f"{realm_url}/groups"
        if group_id:
            url += f"/{group_id}/children"
        try:
            resp = requests.get(url, headers=headers, timeout=10)
            resp.raise_for_status()
        except requests.exceptions.RequestException:
            return []
        result = []
        for group in resp.json():
            full_path = f"{path_prefix}/{group['name']}".replace("//", "/")
            result.append({
                "id": group["id"],
                "name": group["name"],
                "path": full_path
            })
            result.extend(recurse_groups(
                group["id"], full_path, depth + 1, max_depth))
        return result

    return recurse_groups()


def assign_user_to_group(user_id, group_path, token, all_groups):
    matching_group = next((g for g in all_groups if normalize_path(
        g["path"]) == normalize_path(group_path)), None)
    if not matching_group:
        logging.error(f"❌ Group '{group_path}' not found in Keycloak.")
        return False
    headers = {"Authorization": f"Bearer {token}"}
    assign_url = f"{KEYCLOAK_ADMIN_USERS_URL}/{user_id}/groups/{matching_group['id']}"
    resp = requests.put(assign_url, headers=headers, json={})
    return resp.status_code == 204

# === Assign Roles ===


def assign_roles_to_user(user_id, roles_list, token):
    headers = {"Authorization": f"Bearer {token}"}
    realm_url = KEYCLOAK_ADMIN_USERS_URL.rsplit("/users", 1)[0]
    resp = requests.get(f"{realm_url}/roles", headers=headers)
    if resp.status_code != 200:
        logging.error("❌ Failed to fetch roles.")
        return False
    all_roles = resp.json()
    selected_roles = [r for r in all_roles if r["name"] in roles_list]
    if not selected_roles:
        logging.warning(f"⚠️ No matching roles found for: {roles_list}")
        return False
    assign_url = f"{KEYCLOAK_ADMIN_USERS_URL}/{user_id}/role-mappings/realm"
    assign_resp = requests.post(assign_url, headers={
                                **headers, "Content-Type": "application/json"}, json=selected_roles)
    return assign_resp.status_code == 204

# === Worker Function for Each Row ===


def process_user(row, token, all_groups):
    identifier = str(row.get("USERNAME") or row.get("EMAIL", "")).strip()
    user = get_user_by_username_or_email(identifier, token)

    if not user:
        logging.warning(f"User with identifier '{identifier}' not found.")
        return

    user_id = user["id"]
    username = user.get("username", identifier)

    updates = {
        "firstName": str(row.get("FIRSTNAME", user.get("firstName", ""))).strip(),
        "lastName": str(row.get("LASTNAME", user.get("lastName", ""))).strip(),
        "email": str(row.get("EMAIL", user.get("email", ""))).strip(),
        "attributes": {
            "PHONENUMBER": str(row.get("PHONENUMBER", user.get("attributes", {}).get("PHONENUMBER", ""))).strip(),
            "COUNTRY": str(row.get("COUNTRY", user.get("attributes", {}).get("COUNTRY", ""))).strip(),
            "AGENTIDENTIFIER": str(row.get("AGENTIDENTIFIER", user.get("attributes", {}).get("AGENTIDENTIFIER", ""))).strip(),
            "USERCOUNTRY": str(row.get("USERCOUNTRY", user.get("attributes", {}).get("USERCOUNTRY", ""))).strip(),
            "REGION": str(row.get("REGION", user.get("attributes", {}).get("REGION", ""))).strip(),
        }
    }

    group_value = str(row.get("GROUPS", "")).strip()
    role_mapping_value = str(row.get("ROLE MAPPING", "")).strip()

    if update_user(user_id, updates, token):
        logging.info(f"✅ Updated user {username} successfully.")

        password = str(row.get("PASSWORD", "")).strip()
        if password:
            if update_user_password(user_id, password, token):
                logging.info(f"🔐 Password updated for {username}")
            else:
                logging.error(f"❌ Failed to update password for {username}")

        if group_value:
            if assign_user_to_group(user_id, group_value, token, all_groups):
                logging.info(f"👥 Group '{group_value}' assigned to {username}")
            else:
                logging.error(f"❌ Failed to assign group '{group_value}'")

        if role_mapping_value:
            role_list = [r.strip()
                         for r in role_mapping_value.split(",") if r.strip()]
            if assign_roles_to_user(user_id, role_list, token):
                logging.info(f"🛡️ Roles '{role_list}' assigned to {username}")
            else:
                logging.error(f"❌ Failed to assign roles '{role_list}'")
    else:
        logging.error(f"❌ Failed to update user {username}.")

# === Main Process ===


def main():
    start_time = time.time()

    file_path = select_file()
    if not file_path:
        logging.warning("No file selected.")
        return

    df = pd.read_excel(file_path)
    token = get_keycloak_token()
    all_groups = fetch_all_groups(token)

    # Use ThreadPoolExecutor to process each row concurrently
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(process_user, row, token, all_groups)
                   for _, row in df.iterrows()]
        for future in futures:
            future.result()  # Ensures exceptions are raised if any

    logging.info(f"✅ All done in {time.time() - start_time:.2f} seconds.")


if __name__ == "__main__":
    main()

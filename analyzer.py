from androguard.misc import AnalyzeAPK
import re
import json
import hashlib
import os


# ---------- LOAD APK ----------

apk_path = input("Enter APK path: ")

# ---------- FILE INFORMATION ----------

file_size = os.path.getsize(apk_path)

sha256 = hashlib.sha256()

with open(apk_path, "rb") as file:
    while chunk := file.read(8192):
        sha256.update(chunk)

apk_hash = sha256.hexdigest()

a, d, dx = AnalyzeAPK(apk_path)


# ---------- BASIC INFORMATION ----------

package_name = a.get_package()
app_name = a.get_app_name()
version = a.get_androidversion_name()


# ---------- PERMISSIONS ----------

permissions = a.get_permissions()

permission_names = {
    "INTERNET": False,
    "CAMERA": False,
    "RECORD_AUDIO": False,
    "ACCESS_FINE_LOCATION": False,
    "ACCESS_COARSE_LOCATION": False,
    "READ_SMS": False,
    "RECEIVE_SMS": False,
    "READ_CONTACTS": False,
    "WRITE_CONTACTS": False,
    "READ_CALL_LOG": False,
    "WRITE_EXTERNAL_STORAGE": False,
}

for permission in permissions:

    short_name = permission.split(".")[-1]

    if short_name in permission_names:
        permission_names[short_name] = True


# ---------- COMPONENTS ----------

activities = a.get_activities()
services = a.get_services()
receivers = a.get_receivers()
providers = a.get_providers()


# ---------- CODE ----------

method_count = 0

for dex in d:
    for method in dex.get_methods():
        method_count += 1


# ---------- API ANALYSIS ----------

api_keywords = {
    "sms": ["SmsManager"],
    "camera": ["Camera", "CameraManager"],
    "microphone": ["MediaRecorder", "AudioRecord"],
    "location": ["LocationManager"],
    "contacts": ["ContactsContract"],
    "network": [
        "HttpURLConnection",
        "URLConnection",
        "OkHttpClient",
        "Socket"
    ],
    "accessibility": ["AccessibilityService"],
}

api_counts = {}

for category, keywords in api_keywords.items():
    api_counts[category] = 0


for dex in d:

    for method in dex.get_methods():

        class_name = method.get_class_name()

        for category, keywords in api_keywords.items():

            for keyword in keywords:

                if keyword in class_name:
                    api_counts[category] += 1
                    break


# ---------- NETWORK INDICATORS ----------

urls = set()
ip_addresses = set()

url_pattern = r'https?://[^\s"\']+'
ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'


for dex in d:

    for string in dex.get_strings():

        url_matches = re.findall(url_pattern, string)
        ip_matches = re.findall(ip_pattern, string)

        urls.update(url_matches)
        ip_addresses.update(ip_matches)


# ---------- FINAL FEATURES ----------

features = {

    "file": {
        "file_size_bytes": file_size,
        "sha256": apk_hash
    },

    "package_name": package_name,
    "app_name": app_name,
    "version": version,

    "permissions": {
        f"has_{permission.lower()}": int(present)
        for permission, present in permission_names.items()
    },

    "components": {
        "activity_count": len(activities),
        "service_count": len(services),
        "receiver_count": len(receivers),
        "provider_count": len(providers),
    },

    "code": {
        "method_count": method_count,
    },

    "api_usage": api_counts,

    "network": {
        "url_count": len(urls),
        "ip_address_count": len(ip_addresses),
    }
}


# ---------- PRINT RESULT ----------

print("\n========== ALOO PARATHA FEATURES ==========")

print(json.dumps(features, indent=4))

with open("analysis.json", "w") as file:
    json.dump(features, file, indent=4)

print("\nAnalysis saved to analysis.json")
from Crypto.Util.number import getPrime
from datetime import datetime, timedelta

# Store keys of all hospitals/clinics
keys = {}

# Store revoked facilities
revoked_keys = set()

# Audit log
audit_log = []


# ---------------- AUDIT LOG ----------------

def log_operation(operation, facility):

    audit_log.append({
        "time": datetime.now(),
        "operation": operation,
        "facility": facility
    })


# ---------------- KEY GENERATION ----------------

def generate_keys(facility, key_size=1024):

    half_size = key_size // 2

    # Generate p such that p mod 4 = 3
    while True:
        p = getPrime(half_size)

        if p % 4 == 3:
            break

    # Generate q such that q mod 4 = 3
    while True:
        q = getPrime(half_size)

        if q % 4 == 3 and q != p:
            break

    # Rabin public key
    n = p * q

    # Store keys
    keys[facility] = {
        "public": n,
        "private": (p, q),
        "created": datetime.now(),
        "expires": datetime.now() + timedelta(days=365)
    }

    log_operation("KEY GENERATED", facility)

    print("Keys generated for", facility)


# ---------------- KEY DISTRIBUTION ----------------

def distribute_keys(facility):

    if facility not in keys:
        print("Facility not found")
        return

    if facility in revoked_keys:
        print("Access denied - Key revoked")
        return

    public_key = keys[facility]["public"]
    private_key = keys[facility]["private"]

    log_operation("KEY DISTRIBUTED", facility)

    print("\nPublic Key :", public_key)
    print("Private Key:", private_key)


# ---------------- KEY REVOCATION ----------------

def revoke_key(facility):

    if facility in keys:

        revoked_keys.add(facility)

        log_operation("KEY REVOKED", facility)

        print("Key revoked for", facility)


# ---------------- KEY RENEWAL ----------------

def renew_key(facility):

    if facility in keys:

        print("Renewing key for", facility)

        generate_keys(facility)

        revoked_keys.discard(facility)

        log_operation("KEY RENEWED", facility)


# ---------------- CHECK EXPIRY ----------------

def check_expired_keys():

    current_time = datetime.now()

    for facility in keys:

        if current_time >= keys[facility]["expires"]:

            renew_key(facility)


# ---------------- AUDIT REPORT ----------------

def show_audit_log():

    print("\n========== AUDIT LOG ==========")

    for entry in audit_log:

        print(
            entry["time"],
            "|",
            entry["operation"],
            "|",
            entry["facility"]
        )


# ==================================================
# MAIN PROGRAM
# ==================================================

facilities = [
    "City Hospital",
    "Central Clinic",
    "Apollo Hospital"
]

# Generate keys
for facility in facilities:
    generate_keys(facility, 1024)


# ---------------- DISTRIBUTE KEY ----------------

print("\n========== KEY DISTRIBUTION ==========")

distribute_keys("City Hospital")


# ---------------- REVOKE KEY ----------------

print("\n========== KEY REVOCATION ==========")

revoke_key("Central Clinic")

distribute_keys("Central Clinic")


# ---------------- RENEW KEY ----------------

print("\n========== KEY RENEWAL ==========")

renew_key("Central Clinic")


# ---------------- CHECK EXPIRY ----------------

check_expired_keys()


# ---------------- AUDIT LOG ----------------

show_audit_log()
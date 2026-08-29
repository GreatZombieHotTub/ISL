from Crypto.Util.number import getPrime
from datetime import datetime, timedelta


# =========================================================
# RABIN KEY MANAGEMENT SERVICE
# =========================================================

class RabinKeyManagementService:

    def __init__(self, key_size=1024):

        self.key_size = key_size
        self.keys = {}
        self.revoked = set()
        self.audit_log = []


    # -----------------------------------------------------
    # AUDIT LOG
    # -----------------------------------------------------

    def log(self, operation, facility):

        entry = {
            "time": datetime.now(),
            "operation": operation,
            "facility": facility
        }

        self.audit_log.append(entry)


    # -----------------------------------------------------
    # KEY GENERATION
    # -----------------------------------------------------

    def generate_keys(self, facility):

        half_size = self.key_size // 2

        # p and q must be 3 mod 4
        while True:
            p = getPrime(half_size)

            if p % 4 == 3:
                break

        while True:
            q = getPrime(half_size)

            if q % 4 == 3 and q != p:
                break

        n = p * q

        # Public key
        public_key = n

        # Private key
        private_key = (p, q)

        self.keys[facility] = {
            "public": public_key,
            "private": private_key,
            "created": datetime.now(),
            "expires": datetime.now() + timedelta(days=365)
        }

        self.log("KEY_GENERATED", facility)

        print(f"Keys generated for {facility}")


    # -----------------------------------------------------
    # KEY DISTRIBUTION
    # -----------------------------------------------------

    def distribute_keys(self, facility):

        if facility not in self.keys:
            print("Facility not found")
            return

        if facility in self.revoked:
            print("Access denied - key revoked")
            return

        data = self.keys[facility]

        self.log("KEY_DISTRIBUTED", facility)

        return data["public"], data["private"]


    # -----------------------------------------------------
    # KEY REVOCATION
    # -----------------------------------------------------

    def revoke_key(self, facility):

        if facility in self.keys:

            self.revoked.add(facility)

            self.log("KEY_REVOKED", facility)

            print(f"Key revoked for {facility}")


    # -----------------------------------------------------
    # KEY RENEWAL
    # -----------------------------------------------------

    def renew_key(self, facility):

        if facility in self.keys:

            print(f"Renewing key for {facility}")

            self.generate_keys(facility)

            self.revoked.discard(facility)

            self.log("KEY_RENEWED", facility)


    # -----------------------------------------------------
    # AUTOMATIC RENEWAL
    # -----------------------------------------------------

    def check_expired_keys(self):

        current_time = datetime.now()

        for facility in list(self.keys):

            expiry = self.keys[facility]["expires"]

            if current_time >= expiry:

                self.renew_key(facility)


    # -----------------------------------------------------
    # AUDIT REPORT
    # -----------------------------------------------------

    def show_audit_log(self):

        print("\n========== AUDIT LOG ==========")

        for entry in self.audit_log:

            print(
                entry["time"],
                "|",
                entry["operation"],
                "|",
                entry["facility"]
            )


# =========================================================
# MAIN PROGRAM
# =========================================================

kms = RabinKeyManagementService(key_size=1024)


# ---------------------------------------------------------
# Register hospitals and clinics
# ---------------------------------------------------------

facilities = [
    "City Hospital",
    "Central Clinic",
    "Apollo Hospital"
]

for facility in facilities:

    kms.generate_keys(facility)


# ---------------------------------------------------------
# Distribute keys
# ---------------------------------------------------------

print("\n========== KEY DISTRIBUTION ==========")

public_key, private_key = kms.distribute_keys("City Hospital")

print("Public Key :", public_key)
print("Private Key:", private_key)


# ---------------------------------------------------------
# Revoke key
# ---------------------------------------------------------

print("\n========== KEY REVOCATION ==========")

kms.revoke_key("Central Clinic")

kms.distribute_keys("Central Clinic")


# ---------------------------------------------------------
# Renew key
# ---------------------------------------------------------

print("\n========== KEY RENEWAL ==========")

kms.renew_key("Central Clinic")


# ---------------------------------------------------------
# Check expired keys
# ---------------------------------------------------------

kms.check_expired_keys()


# ---------------------------------------------------------
# Audit log
# ---------------------------------------------------------

kms.show_audit_log()
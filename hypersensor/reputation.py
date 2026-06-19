trusted_ranges = [
    "140.82.",      # GitHub
    "142.250.",     # Google
    "142.251.",     # Google
    "216.239.",     # Google
    "104.18.",      # Cloudflare
    "172.64.",      # Cloudflare
    "162.159.",     # Cloudflare
    "20.",          # Microsoft
]

def is_trusted(ip):

    for prefix in trusted_ranges:

        if ip.startswith(prefix):
            return True

    return False
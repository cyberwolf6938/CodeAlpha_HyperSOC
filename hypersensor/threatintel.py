malicious_ips = {
    "1.2.3.4",
    "5.6.7.8",
}
def is_malicious(ip):
    return ip in malicious_ips
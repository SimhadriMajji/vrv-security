import csv
from collections import Counter, defaultdict

LOG_FILE = '/Users/simhadri/Library/Mobile Documents/com~apple~TextEdit/Documents/Sample.log'
OUTPUT_CSV = 'log_analysis_results.csv'
FAILED_LOGIN_THRESHOLD = 3


def parse_log_file(file_path):
    """Parses the log file to extract IP requests, endpoints, and failed login attempts."""
    ip_requests = Counter()
    endpoint_requests = Counter()
    failed_logins = defaultdict(int)

    with open(file_path, 'r') as file:
        for line in file:
            # Extracts IP address
            ip_address = line.split()[0]
            ip_requests[ip_address] += 1

            # Extract endpoint
            if '"' in line:
                endpoint = line.split('"')[1].split()[1]
                endpoint_requests[endpoint] += 1

            # Detect failed login attempts
            if '401' in line or 'Invalid credentials' in line:
                failed_logins[ip_address] += 1

    return ip_requests, endpoint_requests, failed_logins


def identify_most_accessed_endpoint(endpoint_requests):
    """Finds the most accessed endpoint along with its count."""
    return endpoint_requests.most_common(1)[0] if endpoint_requests else (None, 0)


def saves_results_to_csv(ip_requests, most_accessed_endpoint, failed_logins):
    """Saving analysis results in a CSV file."""
    with open(OUTPUT_CSV, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Write requests per IP
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_requests.most_common():
            writer.writerow([ip, count])

        # Write most accessed endpoint
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint", "Access Count"])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])

        # Write suspicious activity
        writer.writerow([])
        writer.writerow(["IP Address", "Failed Login Attempts"])
        for ip, count in failed_logins.items():
            if count > FAILED_LOGIN_THRESHOLD:
                writer.writerow([ip, count])


def display_results(ip_requests, most_accessed_endpoint, failed_logins):
    """Displays analysis results in the terminal."""
    print("IP Address     Request Count")
    for ip, count in ip_requests.most_common():
        print(f"{ip:<20}{count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    print("IP Address      Failed Login Attempts")
    for ip, count in failed_logins.items():
        if count > FAILED_LOGIN_THRESHOLD:
            print(f"{ip:<20}{count}")


def main():
    ip_requests, endpoint_requests, failed_logins = parse_log_file(LOG_FILE)
    # Identifying the most accessed endpoints
    most_accessed_endpoint = identify_most_accessed_endpoint(endpoint_requests)
    display_results(ip_requests, most_accessed_endpoint, failed_logins)
    # Saving the results in CSV file
    saves_results_to_csv(ip_requests, most_accessed_endpoint, failed_logins)


if __name__ == "__main__":
    main()
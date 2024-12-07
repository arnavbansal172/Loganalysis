import re
import sys
import csv
from collections import Counter

#function to count requests per IP address
def count_requests_per_ip_address(log_file):
    try:
        with open(log_file, 'r') as file:    #open the log file in read mode
            log_data = file.read()
    except FileNotFoundError:
        print(f'Error: The file {log_file} does not exist.')     #if file not found, print error message
        sys.exit(1)
    except IOError:
        print(f'Error: The file {log_file} cannot be read.')     #if file cannot be read, print error message
        sys.exit(1)

    ip_addresses = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', log_data)     #find all IP addresses in the log file
    ip_addresses = [ip for ip in ip_addresses if all(0 <= int(octet) <= 255 for octet in ip.split('.'))]    #check invalid IP addresses
    ip_address_count = Counter(ip_addresses)    #count the number of requests per IP address

    sorted_ip_address_count = sorted(ip_address_count.items(), key=lambda x: x[1], reverse=True)   #sort the IP addresses by request count in descending order
    
    print(f'{"IP Address":<20}{"Request Count":<15}')
    for ip_address, count in sorted_ip_address_count:    #print the IP addresses and their request count
        print(f'{ip_address:<20}{count:<15}')
    
    return sorted_ip_address_count


#function to count requests per endpoint
def count_requests_per_endpoint(log_file):
    try:                                                     #same try and catch function as above,
        with open(log_file, 'r') as file:                    #this is ensure that file is read correctly by every function
            log_data = file.read()
    except FileNotFoundError:
        print(f'Error: The file {log_file} does not exist.')
        sys.exit(1)
    except IOError:
        print(f'Error: The file {log_file} cannot be read.')
        sys.exit(1)
    
    #find all endpoints in the log file this is done by finding all the GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH requests
    endpoints = re.findall(r'\"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) (.*?) HTTP/', log_data)  
    
    endpoint_count = Counter(endpoints) #count the number of requests per endpoint
    
    #sort the endpoints by request count in descending order
    sorted_endpoint_count = sorted(endpoint_count.items(), key=lambda x: x[1], reverse=True)
    
    if sorted_endpoint_count:
        most_accessed_endpoint, count = sorted_endpoint_count[0]
        print("Most Frequently Accessed Endpoint:")
        print(f'{most_accessed_endpoint} (Accessed {count} times)')
    else:
        print('No endpoints found in the log file.')
    
    return sorted_endpoint_count

#function to identify brute force attempts
#threshold is set to 10 by default, but can be changed by the user
def identify_brute_force_attempts(log_file, threshold=10):
    try:
        with open(log_file, 'r') as file:
            log_data = file.read()
    except FileNotFoundError:
        print(f'Error: The file {log_file} does not exist.')
        sys.exit(1)
    except IOError:
        print(f'Error: The file {log_file} cannot be read.')
        sys.exit(1)

    #find all failed login attempts in the log file by searching for 401 and Invalid credentials 
    failed_logins = re.findall(r'(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b).*?(401|Invalid credentials)', log_data)
    #count the number of failed login attempts per IP address
    failed_login_count = Counter(ip for ip, _ in failed_logins)
    
    #filter out IP addresses with failed login attempts that exceed the threshold
    flagged_ips = {ip: count for ip, count in failed_login_count.items() if count > threshold}

    if flagged_ips:
        print("Suspicious Activity Detected:")
        print(f'{"IP Address":<20}{"Failed Login Attempts":<25}')
        for ip, count in flagged_ips.items():
            print(f'{ip:<20}{count:<25}')
    else:
        print('No suspicious activity detected.')
    
    return flagged_ips

#function to save the results to a CSV file
def save_to_csv(ip_requests, endpoints, suspicious_activity):
    with open('log_analysis_results.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        
        #write the results to the CSV file
        writer.writerow(['Requests per IP'])
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in ip_requests:
            writer.writerow([ip, count])
        
        writer.writerow([])
        writer.writerow(['Most Accessed Endpoint'])
        writer.writerow(['Endpoint', 'Access Count'])
        writer.writerow([endpoints[0][0], endpoints[0][1]])

        # This can be used to write all the endpoints to the CSV file
        '''for endpoint, count in endpoints:
            writer.writerow([endpoint, count])'''
        
        writer.writerow([])
    
        if suspicious_activity:
            writer.writerow(['Suspicious Activity Detected:'])
            writer.writerow(['IP Address', 'Failed Login Count'])
            for ip, count in suspicious_activity.items():
                writer.writerow([ip, count])
        else:
            writer.writerow(['No suspicious activity detected'])


def main():
    log_file = input("Enter the path to the log file: ")
    
    print("\n")
    ip_requests = count_requests_per_ip_address(log_file)
    print("\n")
    endpoints = count_requests_per_endpoint(log_file)
    print("\n")
    suspicious_activity = identify_brute_force_attempts(log_file)
    print("\n")

    
    save_to_csv(ip_requests, endpoints, suspicious_activity)

if __name__ == '__main__':
    main()
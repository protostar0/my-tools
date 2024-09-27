

from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress only the single InsecureRequestWarning from urllib3
import requests
session = requests.Session()
session.verify=False
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


session.proxies={'http':'http://127.0.0.1:8080','https':'http://127.0.0.1:8080'}
burp0_url = "https://www.hilton.com:443/en/"
burp0_headers = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:129.0) Gecko/20100101 Firefox/129.0", "Accept": "*/*", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Sec-Fetch-Dest": "empty", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Site": "same-origin", "Referer": "https://www.hilton.com/"}
res = session.get(burp0_url, headers=burp0_headers)
len_hilton_main_site=len(res.text)
print(len(res.text))


# Path to your text file
file_path = 'hiltons_domains.txt'

# Open the text file and read it line by line
with open(file_path, 'r') as file:
    for line in file:
        # Remove any leading/trailing whitespace, like newlines
        url = line.strip()
        
        # Skip empty lines
        if not url:
            continue
        
        try:
            # Send a GET request to the URL
            response = session.get(f"https://{url}",headers=burp0_headers,timeout=5)
            
            # Print the URL and status code
            print(f"URL: {url} - Status Code: {len(response.text)}")
            if len_hilton_main_site == len(response.text):
                print(f"this the one {url}===============")
            
            # Optionally, print the response content or do something with it
            # print(response.content)
            
        except requests.exceptions.RequestException as e:
            # Print any errors that occur
            print(f"Error with URL: {url} - {e}")

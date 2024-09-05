#the projects server

from flask import Flask, request, jsonify, render_template
from joblib import load
import pandas as pd
from joblib import load
import re
from urllib.parse import urlparse
import whois
from datetime import datetime
import requests
from bs4 import BeautifulSoup
import socket
import ssl
import dns.resolver 
from tldextract import extract
from urllib.parse import urljoin
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
# Load the trained model and scaler from disk using joblib
model = load('./model/phishing.joblib')
scaler = load('./model/scaler.joblib')

def normalize_url(url):
    if not urlparse(url).scheme:
        url = 'http://' + url
    return url
# Feature 1: Whether the domain is an IP address
def is_ip_address(domain):
  # Simple regex to check if the hostname is an IP address
        ipv4_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
        ipv6_pattern = re.compile(r'^\[?[A-Fa-f0-9:]+\]?$')
        hex_pattern = re.compile(r'^[A-Fa-f0-9]{1,8}$')

        if ipv4_pattern.match(domain) or ipv6_pattern.match(domain) or hex_pattern.match(domain):
            return -1
        return 1

# Feature 2: Whether the url length > 75
def url_bigger_75(url):
        length = len(url)
        if length > 75:
            return -1
        elif 54 <= length <= 75:
            return 0
        else:
            return 1
#Feature 3: Whether tinyURL
def check_if_tinyurl(url):
  # Known URL shortening services (you can expand this list)
  shortening_services = [
        'bit.ly', 'goo.gl', 'shorte.st', 'x.co', 'ow.ly', 't.co', 'tinyurl', 'tr.im',
        'is.gd', 'cli.gs', 'yfrog.com', 'migre.me', 'ff.im', 'tiny.cc', 'url4.eu',
        'twit.ac', 'su.pr', 'twurl.nl', 'snipurl.com', 'short.to', 'BudURL.com',
        'ping.fm', 'post.ly', 'Just.as', 'bkite.com', 'snipr.com', 'fic.kr', 'loopt.us',
        'doiop.com', 'qr.ae', 'adf.ly', 'cur.lv', 'bitly.com', 'tinyurl.com',
        'tiny.cc', 'bit.do', 'db.tt', 'qr.net', 'v.gd', 'tr.im', 'link.zip.net'
         ]
  domain = urlparse(url).netloc
  if domain in shortening_services:
            return -1
  return 1

def expand_url(url):
  try:
    response = requests.head(url, allow_redirects=True)
    return response.url
  except requests.RequestException as e:
    print(f"Error expanding URL: {e}")
    return None

def tinyURL(url):
    if check_if_tinyurl(url) == -1:
        expanded_url = expand_url(url)
        if expanded_url:
            print(f"The expanded URL is: {expanded_url}")
        else:
            print("The URL is not using a known URL shortening service.")
        return -1
    return 1

# Feature 4: Whether '@' symbol is in url
def shtrodel_url(url):
  return -1 if '@' in url else 1


# Feature 5: Whether '//' appears in place > 7 in url
def slash_place(url):
    index = url.find('//')
    if index > 7:
        return -1
    return 1

# Feature 6: Whether '-' appears in url
def include_(domain):
  for char in domain :
    if char == '-':
      return -1
  return 1
    
# Feature 7: Whether the url has multi subdomains
def remove_cctld(domain):
    parts = domain.split('.')
    if len(parts) > 2:
        return '.'.join(parts[:-1])  # Removing the ccTLD
    return domain

def dots(url):
    domain = remove_cctld(urlparse(url).netloc)
    subdomain_count = domain.count('.')
    if subdomain_count > 1:
        return -1
    elif subdomain_count == 1:
        return 0
    else:
        return 1

#Feature 8: Whether (use https and issuer trusted and age of certificate >= 1 year ligitimate) (using https and issuer not trusted suspecious) else phishing
def get_certificate_info(domain):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert['issuer'])
                not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                age = (datetime.utcnow() - not_before).days
                return issuer['commonName'], age, True
    except ssl.SSLError:
        # If SSL fails, it's suspicious, treat as untrusted issuer
        return None, None, False
    except Exception as e:
        # Handle other exceptions (network, timeout, etc.)
        return None, None, False

def check_https_certificate(url):
    domain = urlparse(url).netloc
    issuer, age, is_trusted = get_certificate_info(domain)
    
    if is_trusted:
        if age >= 365:
            return 1  # Legitimate (HTTPS, trusted, certificate age >= 1 year)
        else:
            return 0  # Suspicious (HTTPS, trusted, certificate age < 1 year)
    elif 'https' in url:
        return 0  # Suspicious (HTTPS, but issuer not trusted)
    else:
        return -1  # Phishing (No HTTPS or issuer not trusted)

# Feature 9: Whether the domain expires in 1 year or less
def expires(domain):
    try:
        # Retrieve domain information
        domain_info = whois.whois(domain)
        expiry_date = domain_info.expiration_date
        
        # Handle cases where expiry_date might be a list
        if isinstance(expiry_date, list):
            expiry_date = expiry_date[0]
        
        # Check if expiry_date is available and calculate days to expiration
        if expiry_date and (expiry_date - datetime.now()).days <= 365:
            return -1
    except Exception as e:
        # Log the exception if needed for debugging
        # print(f"Error retrieving domain info: {e}")
        return 1
    
    return 1
# Feature 10: Whether the favicon is loaded from another domain
       
def favicon_not_same_domain(url):
    try:
        # Fetch the content of the URL
        response = requests.get(url)
        response.raise_for_status()
        
        # Parse the HTML content
        soup = BeautifulSoup(response.content, 'html.parser')
        icon_link = soup.find("link", rel=["icon", "shortcut icon", "apple-touch-icon"])
        
        if icon_link and 'href' in icon_link.attrs:
            # Resolve relative URL to absolute URL
            favicon_url = urljoin(url, icon_link['href'])
            favicon_domain = urlparse(favicon_url).netloc
            main_domain = urlparse(url).netloc
            
            # Compare domains
            return -1 if favicon_domain != main_domain else 1
        
    except Exception as e:
        # Log the exception if needed for debugging
        # print(f"Error: {e}")
        return -1
    
    return -1

# Feature 11: Whether a suspecious port is in the preffered status
def check_port_status(url):
    hostname = urlparse(url).hostname
    suspicious_ports = {
        21: 'closed', 22: 'closed', 23: 'closed',
        80: 'open', 443: 'open', 445: 'closed',
        1433: 'closed', 1521: 'closed', 3306: 'closed', 3389: 'closed'
    }
    
    for port, expected_status in suspicious_ports.items():
        actual_status = is_port_open(hostname, port)
        
        # Compare the actual status with the expected status
        if (expected_status == 'open' and not actual_status) or (expected_status == 'closed' and actual_status):
            return -1
    
    return 1

def is_port_open(hostname, port):
    try:
        with socket.create_connection((hostname, port), timeout=3):
            return True  # Port is open
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False  # Port is closed or unreachable

# Feature 12: Whether https is in the domain token
def https_domain(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc if parsed_url.netloc else parsed_url.path
    return -1 if 'https' in domain else 1

# Freature 13: Whether (resuest url < 22% ligitimate) ( esuest url >= 22% and 61% suspecious ) else phishing (what is meant by 61% there is no > or < ...)
# def is_url_with_scheme(url):
    return urlparse(url).scheme in ['http', 'https']

def request_url(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        base_domain = urlparse(url).netloc

        total_resources = 0
        external_resources = 0

        for tag in soup.find_all(['script', 'link', 'img']):
            resource_url = tag.get('src') or tag.get('href')
            if resource_url:
                total_resources += 1
                resource_domain = urlparse(resource_url).netloc
                if resource_domain and resource_domain != base_domain:
                    external_resources += 1

        if total_resources == 0:
            return 1
        percentage = (external_resources / total_resources) * 100
        if percentage < 22:
            return 1
        elif 22 <= percentage < 61:
            return 0
        else:
            return -1
    except Exception as e:
        return -1

# Freature 14: Whether (url of anchor < 31% ligitimate) (url anchor >= 31% and <= 67% suspecious) else phishing

def URL_of_Anchor(url):
   #  url = ensure_http(url)  # Ensure the URL has a protocol
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        anchors = soup.find_all('a', href=True)
        total_anchors = len(anchors)
        
        if total_anchors == 0:
            return 1  # No anchors means no potential phishing

        legitimate = 0
        suspicious = 0
        phishing = 0
        
        for anchor in anchors:
            href = anchor['href']
            if href.startswith('#') or href == '' or href.lower() == 'javascript:void(0)':
                phishing += 1
            elif urlparse(href).netloc == urlparse(url).netloc:
                legitimate += 1
            else:
                suspicious += 1
                
        if legitimate / total_anchors < 0.31:
            return -1  # Phishing
        elif 0.31 <= legitimate / total_anchors <= 0.67:
            return 0  # Suspicious
        else:
            return 1  # Legitimate
    except Exception as e:
        return 0  # If error occurs, return neutral status
    
# Freature 15: Whether (links in <meta> <link> <script> < 17% ligitimate) (links in <meta> <link> <script> >= 17% and <= 81%  suspecious) else phishing 
def Links_in_tags(url):
    # url = ensure_http(url)  # Ensure the URL has a protocol
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        tags = soup.find_all(['meta', 'link', 'script'], href=True)
        total_tags = len(tags)
        
        if total_tags == 0:
            return 1  # No links means no potential phishing

        legitimate = 0
        suspicious = 0
        
        for tag in tags:
            href = tag['href']
            if urlparse(href).netloc == urlparse(url).netloc:
                legitimate += 1
            else:
                suspicious += 1
        
        proportion = legitimate / total_tags
        
        if proportion < 0.17:
            return -1  # Phishing
        elif 0.17 <= proportion <= 0.81:
            return 0  # Suspicious
        else:
            return 1  # Legitimate
    except Exception as e:
        return 0  # If error occurs, return neutral status

# Freature 17: Whether SFH empty or about:blank
def get_sfh(url):
    try:
        # Fetch the content of the URL
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')

        # Extract the 'action' attributes from form tags
        forms = soup.find_all('form', action=True)
        sfh_urls = [form['action'] for form in forms]

        if not sfh_urls:
            return -1  # No SFH found

        domain = urlparse(url).netloc
        if domain.startswith("www."):
            domain = domain[4:]

        for sfh_url in sfh_urls:
            parsed_sfh_url = urlparse(sfh_url)
            domain_sfh = parsed_sfh_url.netloc
            if domain_sfh.startswith("www."):
                domain_sfh = domain_sfh[4:]

            # Check if SFH URL is empty or points to a different domain
            if not domain_sfh or domain_sfh != domain:
                return -1

        return 1  # SFH URLs are from the same domain
    except Exception as e:
        print(f"Error: {e}")
        return 0  # Return neutral status in case of error

#Feature 18: Whether php has mail() or mailto
def check_mailto_links(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        # Find all mailto links
        mailto_links = soup.find_all('a', href=True)
        mailto_urls = [link['href'] for link in mailto_links if link['href'].startswith('mailto:')]
        
        return mailto_urls if mailto_urls else "No mailto links found"
    except Exception as e:
        return "Error fetching mailto links:"
      
def find_email_related_forms(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')
        forms = soup.find_all('form', action=True)
        email_related_actions = []
        for form in forms:
            action = form['action']
            # Check if the action URL contains patterns commonly associated with email handling
            if re.search(r'(send|submit|contact|feedback|mail)\.php$', action):
                email_related_actions.append(action)
        return email_related_actions if email_related_actions else "No email-related forms found"
    except Exception as e:
        return "Error finding email-related forms"
      
def check_malito_mail(url):
    if check_mailto_links(url) == "Error fetching mailto links:": return -1
    if check_mailto_links(url) != None or check_mailto_links(url) != "No mailto links found" :
        return -1
    if find_email_related_forms(url) == "Error finding email-related forms": return -1
    if find_email_related_forms(url) != None or find_email_related_forms(url) != "No email-related form actions found":
        return -1
    return 1

#Feature 19: Whether host name is not included in url
def host_not_in_url(url):
    try:
        hostname = urlparse(url).hostname
        if not hostname:
            return -1
        return 1
    except Exception as e:
        return -1

#Feature 20: Whether the website redirects 4 or more times
def count_redirects(url):
    try:
        response = requests.get(url, allow_redirects=True)
        num_redirects = len(response.history)
        final_url = response.url
        return num_redirects, final_url
    except requests.RequestException as e:
        return -1, None
      
def redirect_alot(url):
    try:
        num_redirects, _ = count_redirects(url)
        if num_redirects ==-1: return -1
        if num_redirects >= 4:
            return -1
        elif 2 <= num_redirects < 4:
            return 0
        else:
            return 1
    except Exception as e:
        return 0

#Feature 21: Whether on_mouse_move status_bar changes
# Define a function to get the current status bar message
def get_status_bar(driver):
  return driver.execute_script("return window.status") 
    
def check_on_mouse_move(url):
    try:
        response = requests.get(url, timeout=20)
        soup = BeautifulSoup(response.content, 'html.parser')
        scripts = soup.find_all('script')
        for script in scripts:
            if 'onmousemove' in script.text.lower() and 'window.status' in script.text.lower():
                return -1  # Likely phishing
        return 1  # Legitimate
    except requests.RequestException:
        return -1  # Treat as phishing if the request fails
    
#Feature 22: Whether right click is disabled  
def right_click(url):
    try:
        response = requests.get(url, timeout=20)
        soup = BeautifulSoup(response.content, 'html.parser')
        scripts = soup.find_all('script')
        for script in scripts:
            if 'oncontextmenu' in script.text.lower():
                return -1  # Right-click disabled
        return 1  # Right-click not disabled
    except requests.RequestException:
        return -1  

#Feature 23: Whether pop_up window contains text field
# Function to check if a popup window contains text fields
def pop_up(url):
    try:
        response = requests.get(url, timeout=20)
        soup = BeautifulSoup(response.content, 'html.parser')
        scripts = soup.find_all('script')
        for script in scripts:
            if 'window.open' in script.text.lower() and ('input' in script.text.lower() or 'textarea' in script.text.lower()):
                return -1  # Pop-up with text field detected
        return 1  # No pop-up with text field
    except requests.RequestException:
        return -1  # Treat as phishing if the request fails
    
#Feature 24: Whether using iframe

def iframe_use(url):
    try:
        response = requests.get(url, timeout=20)
        soup = BeautifulSoup(response.content, 'html.parser')
        iframes = soup.find_all('iframe')
        if iframes:
            return -1  # Iframes found, likely phishing
        return 1  # No iframes, legitimate
    except requests.RequestException:
        return -1  # Treat as phishing if the request fails

#Feature 25: Whether !(age_of_domain >= 6 months)
def get_domain_age(domain):
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            today = datetime.now()
            domain_age_days = (today - creation_date).days
            return domain_age_days
        else:
            print("Creation date not found.")
            return 0  # Return 0 if creation date isn't found
    except Exception as e:
        print(f"Error fetching domain age: {e}")
        return 0  # Return 0 if there's an error

def domain_age(url):
    domain = urlparse(url).netloc
    if domain.startswith("www."):
        domain = domain[4:]
    age_days = get_domain_age(domain)
    return 1 if age_days >= 186 else -1

#Feature 26: Whether no dns records for the domain
def check_dns_records(domain):
    try:
        dns.resolver.resolve(domain, 'A')
        return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return False
    except Exception as e:
        print(f"Error checking DNS records: {e}")
        return False

def no_dns(url):
    domain = urlparse(url).netloc
    if domain.startswith("www."):
        domain = domain[4:]
    return -1 if not check_dns_records(domain) else 1

#Feature 27: Whether website rank = 100,000    
def rank(url):
    return 0

#Feature 28: Whether page rank < 0.2

def Page_Rank(url):
    return 1
    
#Feature 29: Whether webpage not indexed by google
def check_indexed(url):
    search_url = f"https://www.google.com/search?q=site:{url}"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
    }
    response = requests.get(search_url, headers=headers)
    
    if response.status_code == 200:
        if "did not match any documents" in response.text:
            return -1  # Phishing
        else:
            return 1  # Legitimate
    else:
        print("Failed to retrieve search results.")
        return 1  # Default to legitimate if the request fails

#Feature 30: Whether 0 links pointing to the page
def count_external_links(url):
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()  # Raise an exception for HTTP errors

        soup = BeautifulSoup(response.text, 'html.parser')
        links = soup.find_all('a', href=True)
        external_links = 0

        base_domain = urlparse(url).netloc

        for link in links:
            link_url = urlparse(link['href'])
            if link_url.netloc and link_url.netloc != base_domain:
                external_links += 1

        return external_links

    except requests.exceptions.RequestException as e:
        print(f"Error fetching the page222: {e}")
        return None

def reference(url):
    external_links = count_external_links(url)
    
    if external_links is None:
        return None  # Unable to determine the number of links
    elif external_links == 0:
        return -1  # Phishing
    elif 0 < external_links <= 2:
        return 0  # Suspicious
    else:
        return 1  # Legitimate
    
#Feature 31: Whether host belongs to top phishing ips or top phishsing domains
def is_phishing_host(host):
    phishing_domains_url = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
    try:
        response = requests.get(phishing_domains_url)
        response.raise_for_status()
        phishing_domains = response.text.splitlines()
        return host in phishing_domains
    except requests.exceptions.RequestException as e:
        print(f"Error fetching phishing domains: {e}")
        return False

def api_domain_top(url):
    domain = urlparse(url).hostname
    return -1 if is_phishing_host(domain) else 1


def extract_features(url):
    #"""Extract features from the given URL."""
    try:
        parsed_url = urlparse(url)
        url_without_scheme = parsed_url.netloc + parsed_url.path
        url=normalize_url(url)
        domain_info = whois.whois(urlparse(url).netloc)
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        domain = urlparse(url).netloc
        parsed_url = urlparse(url)
        domain = parsed_url.netloc if parsed_url.netloc else parsed_url.path
        if domain.startswith("www."):
            domain = domain[4:]

        features = {
            'having_IP_Address': is_ip_address(domain),
            'URL_Length': url_bigger_75(url),
            'Shortining_Service': check_if_tinyurl(url),
            'having_At_Symbol': shtrodel_url(url),
            'double_slash_redirecting': slash_place(url),
            'Prefix_Suffix': include_(urlparse(url).hostname),
            'having_Sub_Domain': dots(url),
            'SSLfinal_State': check_https_certificate(url),
            'Domain_registeration_length': expires(domain),
            'Favicon': favicon_not_same_domain(url),
            'port':check_port_status(url),
            'HTTPS_token': https_domain(url),
            'Request_URL': request_url(url),
            'URL_of_Anchor': URL_of_Anchor(url),
            'Links_in_tags': Links_in_tags(url),
            'SFH': get_sfh(url),
            'Submitting_to_email': check_malito_mail(url),
            'Abnormal_URL': host_not_in_url(url),
            'Redirect': redirect_alot(url),
            'on_mouseover': check_on_mouse_move(url),
            'RightClick': right_click(url),
            'popUpWidnow': pop_up(url),
            'Iframe': iframe_use(url),
            'age_of_domain': domain_age(url),
            'DNSRecord': no_dns(url),
            'web_traffic': rank(url),
            'Page_Rank': Page_Rank(url),
            'Google_Index': check_indexed(url),
            'Links_pointing_to_page': reference(url),
            'Statistical_report': api_domain_top(url)
        }

        return features

    except Exception as e:
        print(f"Error extracting features from {url}: {e}")
        return None
    
def sanitize_url(url):
    return url.strip()
    
def is_valid_url(url):
    regex = re.compile(
        r'^(?:http|ftp)s?://' # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}|[A-Z0-9-]{2,})|' # domain...
        r'localhost|' # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|' # ...or ipv4
        r'\[?[A-F0-9]*:[A-F0-9:]+\]?)' # ...or ipv6
        r'(?::\d+)?' # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(regex, url) is not None
   
def predict_phishing(url):
    url = sanitize_url(url)  # Sanitize URL before processing
    if not is_valid_url(url):
        print(f"Invalid URL: {url}")
        return None
    # Extract features from the URL
    features = extract_features(url)
    
    # Convert features to a DataFrame
    features_df = pd.DataFrame([features])
    
    # Scale the features
    scaled_features = scaler.transform(features_df)
    
    # Predict using the loaded model
    prediction = model.predict(scaled_features)
    print(features)
    print(prediction)
    # Return the prediction result
    return "Phishing" if prediction[0] == '-1' else "Legitimate"

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    url = data.get('url')
    
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    
    prediction = predict_phishing(url)
    
    if prediction is None:
        return jsonify({'error': 'Invalid or incomplete URL'}), 400
    
    response = {
        'prediction_text': prediction  # Returning "Phishing" or "Legitimate"
    }
    return jsonify(response)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)

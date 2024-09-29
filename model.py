import ipaddress
import re
from bs4 import BeautifulSoup
import requests
import whois
import urllib
import urllib.request
from datetime import datetime
import requests
import json
import csv
import time
import socket
import ssl
import joblib
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score
from sklearn.preprocessing import StandardScaler

# class DataPreprocessor:
#     def __init__(self):
#         # Initialize any preprocessing steps here
#         self.preprocessor = StandardScaler()  # Replace with your actual preprocessing

#     def preprocess(self, data):
#         # Implement your data preprocessing steps here
#         preprocessed_data = self.preprocessor.transform(data)  # Replace with your actual preprocessing
#         return preprocessed_data

# def load_and_predict_from_url(url):
#     # Load the ensemble model from model.pkl
#     try:
#         model = joblib.load("modelmain.pkl")
#     except FileNotFoundError:
#         return "Model file not found."

#     # Fetch data from the provided URL
#     try:
#         response = requests.get(url)
#         data = response.json()  # Assuming the URL returns JSON data, adjust as needed
#     except Exception as e:
#         return f"Error fetching data from URL: {str(e)}"

#     # Initialize a data preprocessor (you may need to customize this class)
#     data_preprocessor = DataPreprocessor()

#     # Preprocess the data
#     preprocessed_data = data_preprocessor.preprocess(data)

#     # Make predictions using the loaded model
#     try:
#         prediction_score = model.predict_proba(preprocessed_data)[:, 1]  # Probability of being phishing
#         prediction = (prediction_score > 0.5).astype(int)  # Convert to binary prediction (0 or 1)
#         return {"prediction": prediction, "prediction_score": prediction_score}
#     except Exception as e:
#         return f"Prediction error: {str(e)}"

# # Example usage:
# if __name__ == "__main__":
#     # Replace 'your_url_here' with the actual URL from which you want to fetch data.
#     input_url = 'your_url_here'
#     result = load_and_predict_from_url(input_url)
#     print("Phishing Prediction:", result["prediction"])
#     print("Prediction Score:", result["prediction_score"])


global BASE_SCORE
global PROPERTY_SCORE_WEIGHTAGE
BASE_SCORE = 50  # default trust_ score of url out of 100
PROPERTY_SCORE_WEIGHTAGE = {
    'domain_rank': 0.9,
    'domain_age': 0.3,
    'is_url_shortened': 0.8,
    'hsts_support': 0.1,
    'ip_present': 0.8,
    'url_redirects': 0.2,
    'too_long_url': 0.1,
    'too_deep_url': 0.5,
    'content': 0.1
}



# check whether the link is active or not
def validate_url(url):
    try:
        response = requests.get(url)
        return response.status_code

    except requests.exceptions.RequestException:
        return False

def include_protocol(url):
    try:
        if not url.startswith('http://') and not url.startswith('https://'):
            url = 'https://' + url
        return url

    except:
        return url

# get domain rank if it exists in top 1M list
def get_domain_rank(domain):
    
    with open('static/data/sorted-top1million.txt') as f:
        top1million = f.read().splitlines()

    is_in_top1million = binary_search(top1million, domain)

    if is_in_top1million == 1:
        with open('static/data/domain-rank.json', 'r') as f:
            domain_rank_dict = json.load(f)
        rank = domain_rank_dict.get(domain, 0)
        return int(rank)
    else:
        return 0


# binary search
def binary_search(arr, x):
    low = 0
    high = len(arr) - 1
    while low <= high:
        mid = (low + high) // 2
        if arr[mid] == x:
            return 1
        elif arr[mid] < x:
            low = mid + 1
        else:
            high = mid - 1
    return 0

# get whois data of domain
def whois_data(domain):
    try:
        whois_data = whois.whois(domain)
        creation_date = whois_data.creation_date
        data = {}

        if type(creation_date) is list:
            creation_date = creation_date[0]
            whois_data['creation_date'] = [d.strftime('%Y-%m-%d %H:%M:%S') for d in whois_data.creation_date]
        # else:
        #     whois_data['creation_date'] = whois_data.creation_date.strftime('%Y-%m-%d %H:%M:%S')

        if type(whois_data.updated_date) is list:
            whois_data['updated_date'] = [d.strftime('%Y-%m-%d %H:%M:%S') for d in whois_data.updated_date]
        # else:
        #     whois_data['updated_date'] = whois_data.updated_date.strftime('%Y-%m-%d %H:%M:%S')

        if type(whois_data.expiration_date) is list:
            whois_data['expiration_date'] = [d.strftime('%Y-%m-%d %H:%M:%S') for d in whois_data.expiration_date]
        # else:
        #     whois_data['expiration_date'] = whois_data.expiration_date.strftime('%Y-%m-%d %H:%M:%S')


        if creation_date == None:
            age = 'Not Given'
        else:
            age = (datetime.now() - creation_date).days / 365 

        for prop in whois_data:
            if type(whois_data[prop]) is list:
                data[pascal_case(prop)] = ', '.join(whois_data[prop])
            else:
                data[pascal_case(prop)] = whois_data[prop]

        return {'age':age, 'data':data}

    except Exception as e:
        print(f"Error: {e}")
        return False


def pascal_case(s):
    result = s.replace('_',' ').title()
    return result


# check for HSTS support
def hsts_support(url): # url should be http / https as prefix
    try:
        response = requests.get(url)
        headers = response.headers
        if 'Strict-Transport-Security' in headers:
            return 1
        else:
            return 0
    except:
        return 0


# check for URL shortening services
def is_url_shortened(domain): 
    try:
        with open('static/data/url-shorteners.txt') as f:
            services_arr = f.read().splitlines()
        
        for service in services_arr:
            if service in domain:
                return 1
        return 0
    except:
        return 0


# check if an IP is present in the URL
def ip_present(url):
    try:
        ipaddress.ip_address(url)
        result = 1
    except:
        result = 0
    return result


# check for website redirects
def url_redirects(url):
    try:
        response = requests.get(url)
        if len(response.history) > 1:
            # URL is redirected
            url_history = [] # returns array of redirected URLs
            for resp in response.history:
                url_history.append(resp.url)
            return url_history
        else:
            return 0
    except Exception as e:
        # print(f"Error: {e}")
        return 0


# check whether the URL is too long 
def too_long_url(url):
    if len(url) > 75:
        return 1
    else:
        return 0


# check whether the URL is too deep 
def too_deep_url(url):
    slashes = -2 # to skip first two slashes after protocol, i.e. https://
    for i in url:
        if i == '/':
            slashes += 1

    if slashes > 5:
        return 1
    else:
        return 0



# check whether the URL is having 
def content_check(url):
    try:

        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')

        result = {'onmouseover':0, 'right-click':0, 'form':0, 'iframe':0, 'login':0, 'popup':0}

        # check if onmouseover is enabled
        if soup.find(onmouseover=True):
            result['onmouseover'] = 1


        # check if right-click is disabled
        if soup.find_all('body', {'oncontextmenu': 'return false;'}):
            result['right-click'] = 1


        # check if there are any forms present
        if soup.find_all('form'):
            result['form'] = 1

        # check if there are any iframes present
        if soup.find_all('iframe'):
            result['iframe'] = 1

        # check if there are any login keyword present
        if soup.find_all(text=re.compile('password|email|forgotten|login')):
            result['login'] = 1

        # check if there are any pop-ups present
        if soup.find_all('div', {'class': 'popup'}):
            result['popup'] = 1
        
        return result

    except Exception as e:
        # print(f"Error: {e}")
        return 0



def phishtank_search(url):

    try:
        endpoint = "https://checkurl.phishtank.com/checkurl/"
        response = requests.post(endpoint, data={"url": url, "format": "json"})
        data = json.loads(response.content)
        if data['results']['valid'] == True:
            return 1
        return 0

    except Exception as e:
        # print(f"Error: {e}")
        return 0


def get_ip(domain):

    try:
        ip = socket.gethostbyname(domain)
        return ip

    except Exception as e:
        print(f"Error: {e}")
        return 0



def get_certificate_details(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as sslsock:
                cert = sslsock.getpeercert()


                # Certificate Authority (CA) information
                issuer = dict(x[0] for x in cert['issuer'])
                if 'organizationName' in issuer:
                    ca_info = issuer['organizationName']
                else:
                    ca_info = issuer['commonName']


                # Certificate validity period
                not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_to_expiry = (not_after - datetime.now()).days

                # Certificate revocation status
                revoked = False
                for crl in cert.get('crlDistributionPoints', ()):
                    try:
                        crl_data = ssl.get_server_certificate((crl.split('//')[1]).split('/')[0])
                        crl_obj = ssl.load_crl_der(ssl.PEM_to_DER_cert(crl_data))
                        if crl_obj.get_revoked_certificate_by_serial_number(cert['serialNumber']):
                            revoked = True
                            break
                    except Exception:
                        pass

                # Cipher suite
                cipher = sslsock.cipher()
                cipher_suite = cipher[0]

                # SSL/TLS version
                version = sslsock.version()

                # Common name and Subject Alternative Names (SANs)
                subject = dict(x[0] for x in cert['subject'])
                common_name = subject['commonName']
                sans = [x[1] for x in cert['subjectAltName'] if x[0] == 'DNS']

                return {
                    'Issued By': ca_info,
                    'Issued To': common_name,
                    'Valid From': not_before.strftime('%Y-%m-%d %H:%M:%S %Z'),
                    # 'sans': sans
                    'Valid Till': not_after.strftime('%Y-%m-%d %H:%M:%S %Z'),
                    'Days to Expiry': days_to_expiry,
                    'Version': version,
                    'Is Certificate Revoked': revoked,
                    'Cipher Suite': cipher_suite
                    # 'chain_info': chain_info,
                }
    except Exception as e:
        print(f"Error: {e}")
        return 0


# TEST FUNCTION TO ADD NEW URL CHECKS
def test(domain):
    
    with open('sorted-top1million.txt') as f:
        top1million = f.read().splitlines()
        

# res = content_check(url)
# print(res)


def calculate_trust_score(current_score, case, value):

    score = current_score

    if case == 'domain_rank':
        if value == 0:  # not in top 10L rank
            score = current_score #- (PROPERTY_SCORE_WEIGHTAGE['domain_rank'] * BASE_SCORE * 0.5)
        elif value < 100000:  # in top 1L rank
            score = current_score + (PROPERTY_SCORE_WEIGHTAGE['domain_rank'] * BASE_SCORE)
        elif value < 500000:  # in 1L - 5L rank
            score = current_score + (PROPERTY_SCORE_WEIGHTAGE['domain_rank'] * BASE_SCORE * 0.8)
        else:  # in 5L - 10L rank
            score = current_score + (PROPERTY_SCORE_WEIGHTAGE['domain_rank'] * BASE_SCORE * 0.6)
        return score

    elif case == 'domain_age':
        if value < 5:
            score = current_score - (PROPERTY_SCORE_WEIGHTAGE['domain_age'] * BASE_SCORE)
        elif value >= 5 and value < 10:
            score = current_score
        elif value >= 10:
            score = current_score + (PROPERTY_SCORE_WEIGHTAGE['domain_age'] * BASE_SCORE)
        return score

    elif case == 'is_url_shortened':
        if value == 1:
            score = current_score - (PROPERTY_SCORE_WEIGHTAGE['is_url_shortened'] * BASE_SCORE)
        return score

    elif case == 'hsts_support':
        if value == 1:
            score = current_score + (PROPERTY_SCORE_WEIGHTAGE['hsts_support'] * BASE_SCORE)
        else:
            score = current_score - (PROPERTY_SCORE_WEIGHTAGE['hsts_support'] * BASE_SCORE)
        return score

    elif case == 'ip_present':
        if value == 1:
            score = current_score - (PROPERTY_SCORE_WEIGHTAGE['ip_present'] * BASE_SCORE)
        return score

    elif case == 'url_redirects':
        if value:
            score = current_score - (PROPERTY_SCORE_WEIGHTAGE['url_redirects'] * BASE_SCORE)
        return score

    elif case == 'too_long_url':
        if value == 1:
            score = current_score - (PROPERTY_SCORE_WEIGHTAGE['too_long_url'] * BASE_SCORE)
        return score

    elif case == 'too_deep_url':
        if value == 1:
            score = current_score - (PROPERTY_SCORE_WEIGHTAGE['too_deep_url'] * BASE_SCORE)
        return score
    
# # Define a function to train and evaluate a Random Forest classifier
# def train_and_evaluate_rf_model(data):
#     X = [extract_features(url) for url, _ in data]
#     y = [label for _, label in data]

#     X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

#     classifier = RandomForestClassifier(n_estimators=100, random_state=42)
#     classifier.fit(X_train, y_train)

#     y_pred = classifier.predict(X_test)

#     accuracy = accuracy_score(y_test, y_pred)
#     print(f"Accuracy: {accuracy}")

#     return classifier

# # Example usage:
# if __name__ == "__main__":
#     # Load your dataset or collect data with labels (0 for safe, 1 for suspicious)
#    data = []
# with open('your_dataset.csv', 'r') as csvfile:
#     reader = csv.reader(csvfile)
#     for row in reader:
#         url = row[0]  # Assuming the URL is in the first column
#         label = int(row[1])  # Assuming the label is in the second column
#         data.append((url, label))

#     # Train and evaluate the Random Forest model
#     trained_rf_classifier = train_and_evaluate_rf_model(data)

#     # Test URL for trust score calculation
#     url_to_check = "https://new-url.com"

#     # Calculate initial trust score
#     initial_score = BASE_SCORE  # Use your existing BASE_SCORE value
#     print(f"Initial Trust Score: {initial_score}")

#     # Calculate trust score with Random Forest model
#     updated_score = calculate_trust_score_with_ml(url_to_check, initial_score, trained_rf_classifier)
#     print(f"Updated Trust Score: {updated_score}")
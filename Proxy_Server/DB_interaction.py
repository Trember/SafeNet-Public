import base64
import pymongo
from Constants import SafeBrowsingConsts as sbd
from Constants import HostNamesDBConsts 
import socket
import ssl
import json
import hashlib
import re
from datetime import datetime
from base64 import b64encode
from urllib.parse import urlparse, urlunparse, quote, unquote, urlsplit
import threading
import asyncio
import time 

class DataBase():

    def __init__(self):
        self.client = pymongo.MongoClient(sbd.DATABAS_DIR)
        self.db = self.client['SafeNet']


class URL_Database(DataBase):

    def __init__(self,HN_db):
        super().__init__()
        self.collection = self.db['threat_list'] 
        self.HostName_db = HN_db

    def insert_data_to_db(self,data):
        data_type = data['listUpdateResponses'][0]['threatType']
        data["date"] = str(datetime.now())
        threatType_cursor = self.collection.find({"listUpdateResponses.threatType" : data_type})
        amount_of_files = len([x for x in threatType_cursor])

        if(amount_of_files < 1):
            self.collection.insert_one(data)
            #print("inserted")
        else:
            self.collection.find_one_and_replace({"listUpdateResponses.threatType" : data_type}, data)
            #print("replaced")
        #result = self.collection.insert_one(data)  # Insert one document
        #print("Inserted document with ID:", result.inserted_id)

    # Function to check if a hash matches any hash prefixes
    def check_url_in_threat_list(self,url):
        # Get list of all possable url combos
        urls = self.__extract_possable_urls(url) 
        # Generate the hash for the URLs
        hash_bytes = [self.__generate_url_hash(x) for x in urls]
        #print(hash_bytes)

        # Extract the first 4 bytes (or the appropriate prefix length)
        hash_prefixs = [x[:8] for x in hash_bytes]  # Use first 4 bytes as the prefix
        print(hash_prefixs)

        # Search the collection for matching hash prefixes
        for threat_type in sbd.THREAT_TYPES: 
            raw_hash = self.collection.find_one({"listUpdateResponses.threatType" : threat_type},{"_id": 0, "listUpdateResponses.additions.rawHashes" : 1})
            if (raw_hash is not None):
                raw_Hex = base64.b64decode(raw_hash["listUpdateResponses"][0]["additions"][0]["rawHashes"]["rawHashes"]).hex()
                for hash_prefix in hash_prefixs:
                    if(hash_prefix in raw_Hex):
                        return True
        return False    
    
    def test(self,hash_prefix):
        matching_prefix = self.collection.find_one({
            "listUpdateResponses.additions.rawHashes.rawHashes": {"$regex": hash_prefix}  # Convert to hex string
            })
        if (matching_prefix is not None): # Cheaking if the find_one function found something
            return True
        return False

    
    # Function to normalize a URL and generate its hash
    def __generate_url_hash(self,url):
        # Normalize the URL
        normalized_url = self.__canonicalize_url(url)
        normalized_url = urlsplit(normalized_url)
        normalized_url_str = normalized_url.scheme.lower() + "://" + \
                            normalized_url.netloc.lower() + \
                            normalized_url.path.lower()
        # Hash the normalized URL using SHA-256
        #print(normalized_url_str)
        hash_object = hashlib.sha256(normalized_url_str.encode('utf-8'))
        hash_bytes = hash_object.digest()

        #print(hash_bytes)
        return hash_bytes.hex() #b64encode(hash_bytes).decode('utf-8')
    
    def __canonicalize_url(self,url):
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        if parsed.port in (80, 443):
            netloc = parsed.hostname
        path = quote(unquote(parsed.path))
        query = quote(unquote(parsed.query), safe="=&")
        return urlunparse((scheme, netloc, path, parsed.params, query, ''))
    
    def __extract_possable_urls(self, url):
        #(url)
        list_of_hostnames = []
        pattern = "^(.{5,6}\/\/)(.*)"
        match = re.match(pattern,url)
        list_of_urls = []
        if match:
            http_start = match.group(1)
            split_url = match.group(2)
        else:
            http_start = "https://"
            split_url = url

        split_url = re.split(r"\/",split_url)
        # Filter out empty strings
        split_url = [s for s in split_url if s]
        split_params = re.split(r'\?' ,split_url[-1])
        del split_url[-1]
        start_param_index = -1
        if len(split_params) > 1:
            start_param_index = len(split_url) - len(split_params) + 1
        for x in split_params:
            split_url.append(x) 

        host_url = re.split("\." , split_url[0])
        # Cheaking if the end like ".com" is two word or one like "co.il"
        hostnames_list = self.HostName_db.get_hostname_list()
        if((host_url[-2].upper() in hostnames_list) and (host_url[-1].upper() in hostnames_list)):
            host_url[-2] = host_url[-2] + '.' + host_url[-1]
            del host_url[-1]

        # Make sure there are only the last five hostname components
        if(len(host_url) > 5):
            list_of_hostnames.append(http_start + split_url[0] + "/")
            while(len(host_url) > 5):
                del host_url[0]

        # Creating the Hostname possible combination
        if(not host_url[0].isnumeric()):
            for i in range(len(host_url)-1): # The length is -1 so that in the last interation the host_url will stay with 2 parameters.
                url = http_start
                for x in host_url:
                    url += x + "."
                url = url[:-1]
                url += "/"
                list_of_hostnames.append(url)
                del host_url[0]
            del split_url[0]
        else:
            list_of_hostnames.append(http_start + split_url[0] + "/")
            del split_url[0]

        # Adding pathing to the combinations
        for i in list_of_hostnames:
            list_of_urls.append(i)
            end_char = "/"
            for x in split_url:
                if(start_param_index != -1):
                    if(split_url.index(x) == len(split_url)-1):
                        end_char = ""
                    elif(split_url.index(x) >= start_param_index):
                        end_char = "?"
                list_of_urls.append(list_of_urls[-1] + x + end_char)
                
        for x in list_of_urls:
            if(x[-1] == '?' or ("html/" in x[-5:])):
                index = list_of_urls.index(x)
                list_of_urls[index] = list_of_urls[index][:-1]
        list_of_urls.append(url)
        return list_of_urls

    # Returns the currnet data update state
    def GetState(self, threatType):
        client_state = self.collection.find_one({"listUpdateResponses.threatType" : threatType}, {"_id": 0,"listUpdateResponses.newClientState":1})
        if client_state != None:
            return client_state['listUpdateResponses'][0]['newClientState']
        return ""
    
    def __Is_update_needed(self,threatType):
        update_data = self.collection.find_one({"listUpdateResponses.threatType" : threatType}, {"_id": 0,"minimumWaitDuration" : 1 ,"date": 1})
        updated_on = datetime.strptime(update_data['date'], r'%Y-%m-%d %H:%M:%S.%f')
        if((datetime.now() - updated_on).seconds > int(update_data['minimumWaitDuration'][:-1].split('.')[0])):
            return (True,  int(update_data['minimumWaitDuration'][:-1].split('.')[0]) - (datetime.now() - updated_on).seconds)
        return (False, int(update_data['minimumWaitDuration'][:-1].split('.')[0]) - (datetime.now() - updated_on).seconds)
    
    def maintain(self,safe_browsing_client):
        while(True):
            smallest_wait_time = -1
            for threatType in sbd.THREAT_TYPES:
                    update_data = self.__Is_update_needed(threatType)
                    if(update_data[0]):
                        safe_browsing_client.SetUpSSLSocket()
                        safe_browsing_client.CreateHTTPRequset(threatType)
                        safe_browsing_client.SendAndRecive()
                    if(smallest_wait_time == -1 or smallest_wait_time > update_data[1]):
                        smallest_wait_time = update_data[1]
            time.sleep(smallest_wait_time)



class Hostname_Database(DataBase):

    def __init__(self):
        super().__init__()
        self.collection = self.db['HostNames']
        self.get_hostname_databse()

    # Acts both as a insert for first time, and for update to the database
    def get_hostname_databse(self):
        # Create a socket and connect
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Create sll context
        context = ssl.SSLContext(check_hostname = False)
        # Wrap in SSL for secure communication
        #ssl_sock = context.wrap_socket(sock)
        ssl_sock = sock
        # Connect to the host and port
        ssl_sock.connect((HostNamesDBConsts.HOST, HostNamesDBConsts.PORT))

        # Construct HTTP request
        http_request = (
                    "GET /TLD/tlds-alpha-by-domain.txt HTTP/1.1\r\n"  # Use the correct HTTP version
                    "Host: data.iana.org\r\n"  # "Host" header is mandatory in HTTP/1.1
                    "Connection: close\r\n"  # Closes the connection after the request
                    "User-Agent: MyPythonClient/1.0\r\n"  # Good practice to include a user agent
                    "\r\n"  # The blank line that separates headers from the body (even if there's no body)
                    )

        # Send the request
        ssl_sock.sendall(http_request.encode())

        # Receive the response
        response = b''
        while True:
            data = ssl_sock.recv(4096)
            if not data:
                break
            response += data

        # Close the socket connection
        ssl_sock.close()


        # Split response into headers and body
        response_parts = response.decode().split("\r\n\r\n", 1)  # Split at the first double CRLF
        body_str = response_parts[1] if len(response_parts) > 1 else ""  # HTTP body

        body_str = body_str.split('\n')[1:-1]
        self.insert_to_database(body_str)

    def Is_update_needed(self):
        update_data = self.collection.find_one({"name" : "HostNames"}, {"_id": 0,"date": 1})
        updated_on = update_data['date']
        if((datetime.now() - updated_on).days > HostNamesDBConsts.MINIMUM_WAIT_DURATION):
            return (True, (HostNamesDBConsts.SECONDS_IN_A_DAY - (datetime.now() - updated_on).seconds))
        return (False, (HostNamesDBConsts.SECONDS_IN_A_DAY - (datetime.now() - updated_on).seconds))


    def maintain(self):
        while(True):
            update_data = self.Is_update_needed()
            if(update_data[0]):
                self.get_hostname_databse()
            time.sleep(update_data[1])

    
    # Inserts or updates the database 
    def insert_to_database(self,data):
        hostnames_cursor = self.collection.find()
        amount_of_fils = len([x for x in hostnames_cursor])

        if(amount_of_fils < 1):
            self.collection.insert_one(dict(name = "HostNames", state = "Inserted", date = datetime.now() , hostnames = " ".join(data)))
            #print("inserted")
        else:
            self.collection.find_one_and_replace({"name" : "HostNames"}, {"name" : "HostNames","state" : "Updated" , "date" : datetime.now(), "hostnames" : " ".join(data)})
            #print("replaced")

    # Extract a list of Hostnames from the database
    def get_hostname_list(self):
        return self.collection.find_one({"name" : "HostNames"}, {"_id" : 0 ,"hostnames" : 1})["hostnames"].split(" ")


class SafeBrowsingClient():

    def __init__(self,URL_db):
        self.db = URL_db
        
        for threatType in sbd.THREAT_TYPES:
            self.SetUpSSLSocket()
            self.CreateHTTPRequset(threatType)
            self.SendAndRecive()


    def CreateHTTPRequset(self,threatType):
        # Define the JSON body
        request_body = {
            "client": {
                "clientId": "SafeNet",
                "clientVersion": "1.0"
            },
            "listUpdateRequests": [
                {
                    "threatType": threatType,
                    "platformType": "ANY_PLATFORM",
                    "threatEntryType": "URL",
                    "state": "",#self.db.GetState(threatType),  # No state for initial request
                    "constraints": {
                        "region": "US",
                        "supportedCompressions": ["RAW"]
                    }
                }
            ]
        }

        # Convert to JSON string and get the byte length
        json_body = json.dumps(request_body)
        content_length = len(json_body)

        # Construct HTTP request
        self.http_request = (
            f"POST /v4/threatListUpdates:fetch?key={sbd.API_KEY} HTTP/1.1\r\n"
            f"Host: {sbd.HOST}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {content_length}\r\n"
            f"Connection: close\r\n"  # Close the connection after the response
            f"\r\n"  # Blank line to end the headers
            f"{json_body}"  # The request body
        )

    def SetUpSSLSocket(self):
        # Create a socket and connect
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Create sll context
        self.context = ssl.SSLContext(check_hostname = False)
        # Wrap in SSL for secure communication
        self.ssl_sock = self.context.wrap_socket(sock)
        # Connect to the host and port
        self.ssl_sock.connect((sbd.HOST, sbd.PORT))

    def SendAndRecive(self):
        # Send request to API
        # Send the HTTP request
        self.ssl_sock.sendall(self.http_request.encode())

        # Buffer for response
        response_buffer = b""

        # Read from the socket until no more data is available
        while True:
            data = self.ssl_sock.recv(4096)  # Read 4096 bytes at a time
            if not data:
                break
            response_buffer += data

        # Decode the response to a string
        response_str = response_buffer.decode()

        # Split response into headers and body
        response_parts = response_str.split("\r\n\r\n", 1)  # Split at the first double CRLF
        headers_str = response_parts[0]  # HTTP headers
        body_str = response_parts[1] if len(response_parts) > 1 else ""  # HTTP body

        #print(body_str)
        # Parse JSON body if available
        response_body = json.loads(body_str) if body_str else {}

        # Close the socket
        self.ssl_sock.close()

        # Output the HTTP status code and response
        #print("Headers:", headers_str)
        #print("Body:", response_body)
        #print(type(response_body))
        #print("--------------\n")
        #print(response_body["listUpdateResponses"][0]["additions"][0]["rawHashes"]["rawHashes"])
        #print("--------------\n")
        #response_body["listUpdateResponses"][0]["additions"][0]["rawHashes"]["rawHashes"] = re.findall(r"(.{6})",(response_body["listUpdateResponses"][0]["additions"][0]["rawHashes"]["rawHashes"]))
        self.db.insert_data_to_db(response_body)
        self.ssl_sock.close()


def init():
    Host_names_db = Hostname_Database()
    print("Hostnames Up ")
    URL_db = URL_Database(Host_names_db)
    print("URL Up")
    safe_browing_client = SafeBrowsingClient(URL_db)
    print("Up to Date")
    maintain(URL_db, Host_names_db, safe_browing_client)
    return URL_db

def maintain(url_db, HN_db, safe_browing_client):
    threading.Thread(target=url_db.maintain, args=(safe_browing_client,)).start()
    threading.Thread(target=HN_db.maintain, args=()).start()

    


if (__name__ == "__main__"):
    HN_db = Hostname_Database()
    URL_db = URL_Database(HN_db)
    #safe_browing_client = SafeBrowsingClient(URL_db)
    print(URL_db.check_url_in_threat_list("testsafebrowsing.appspot.com"))
    #HN_db.get_hostname_databse()
    #print(HN_db.get_hostname_list())
    #URL_db.insert_data_to_db(datas)
    #print(URL_db.test("AAA"))
    #print(URL_db.Is_update_needed("MALWARE"))
    #print(HN_db.Is_update_needed())
    #init()
    
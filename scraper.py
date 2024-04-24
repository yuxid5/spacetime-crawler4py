import re
from urllib.parse import urlparse, urljoin #use to find abs url
from bs4 import BeautifulSoup #this import is used to parsing html
from urllib.robotparser import RobotFileParser # to handle robot file
import hashlib

visited_hashes = []

def get_fingerprint(lisOfAllToken): #use this function to calculate hash value
    tokenFrequency = computeWordFrequencies(lisOfAllToken)#compute frequency
    vector = [0] * 64 #initialize vector(fingerprint)
    for key, (weight, binary_string) in tokenFrequency.items():
        for i, bit in enumerate(binary_string):
            # if 0 mult -1, 1 otherwise
            multiplier = 1 if bit == '1' else -1
            # weight binary
            vector[i] += weight * multiplier
    #generating fingerprint
    for i in range(64):
        if vector[i] > 0:
            vector[i] = 1
        else:
            vector[i] = 0
    return vector

def get_score(fingerprint1, fingerprint2):
    score = 0
    finalfingerprint = [0]*64
    for i in range(64): #bitwise two fingerprint
        if fingerprint1[i] == fingerprint2[i]:
            finalfingerprint[i] = 1
        else:
            finalfingerprint[i] = 0
    for value in finalfingerprint:
        score += value
    return score/64

def tokenize(text):
    tokens = []
    temp_word = ""
    for char in text:
        if '0' <= char.lower() <= '9' or 'a' <= char.lower() <= 'z':
            temp_word += char.lower()
        else:
            if temp_word:
                tokens.append(temp_word)
                temp_word = ""
    if temp_word:  # Add the last word if there is one
        tokens.append(temp_word)
    return tokens


def computeWordFrequencies(listToken):
    wordDict = {}
    for item in listToken:
        word_hashvalue = simple_hash_to_binary(item)
        if item not in wordDict:
            wordDict[item] = [1,word_hashvalue]
        else:
            wordDict[item][0] +=1
    return wordDict

def simple_hash_to_binary(value): #compute binary value of word hash value
    hash_object = hashlib.sha256(value.encode())
    hex_dig = hash_object.hexdigest()
    hash_int = int(hex_dig, 16) #conver hex to int
    lower_64_bits = hash_int & ((1 << 64) - 1) #get low 64 bits
    binary_representation = bin(lower_64_bits)[2:].zfill(64) #convert to bin
    return binary_representation

def check_all_sim(fingerprint2): #check for log
    global visited_hashes
    for value in visited_hashes:
        if get_score(value, fingerprint2) > 0.9:
            return False
    return True


def is_valid_new_page(resp): #to determine whether a new page
    global visited_hashes
    soup = BeautifulSoup(resp.raw_response.content, 'html.parser')
    tokens = tokenize(soup.get_text(separator=' ', strip=True)) #check the similarity page.
    fingerprint2 = get_fingerprint(tokens)
    if not check_all_sim(fingerprint2):
        return False
    if len(tokens) < 50 or len(tokens) > 10000000: #define valid page
        return False
    if 20 * 1024 > len(resp.raw_response.content) or len(resp.raw_response.content) > 1 * 1024 * 1024: #define valid page size 20KB-5MB
        return False
    if not checkrobots(resp.url):
        return False
    visited_hashes.append(fingerprint2)
    return True

def is_relative_url(url):
    parsed_url = urlparse(url)
    return not parsed_url.scheme and not parsed_url.netloc

def scraper(url, resp):
    links = extract_next_links(url, resp)
    return [link for link in links if is_valid(link)]


def extract_next_links(url, resp):
    # Implementation required.
    # url: the URL that was used to get the page
    # resp.url: the actual url of the page
    # resp.status: the status code returned by the server. 200 is OK, you got the page. Other numbers mean that there was some kind of problem.
    # resp.error: when status is not 200, you can check the error here, if needed.
    # resp.raw_response: this is where the page actually is. More specifically, the raw_response has two parts:
    #         resp.raw_response.url: the url, again
    #         resp.raw_response.content: the content of the page!
    # Return a list with the hyperlinks (as strings) scrapped from resp.raw_response.content
    links_collection = []
    if resp.status == 200 and resp.raw_response is not None: #valid url
        if(is_valid_new_page(resp)):
            soup = BeautifulSoup(resp.raw_response.content, 'html.parser') #parse html
            for n_url in soup.find_all('a', href=True):

                if is_relative_url(n_url['href']):
                    abs_url = urljoin(url, n_url['href'])
                else:
                    abs_url = n_url['href']

                if urlparse(abs_url).fragment != '':
                    abs_url = abs_url.split("#")[0]

                if is_valid(abs_url):
                    #print(soup.get_text(separator=' ', strip=True)) #for test
                    links_collection.append(abs_url)
    else:
        pass
    return links_collection #return list

def is_valid(url):
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.
    try:
        parsed = urlparse(url)
        if parsed.scheme not in set(["http", "https"]):
            return False

        if '.' not in parsed.netloc: #check legal netloc
            return False
        
        if (parsed.netloc not in set(["ics.uci.edu", "cs.uci.edu", "informatics.uci.edu", "stat.uci.edu"]) 
            and parsed.netloc.split('.', 1)[1] not in set(["ics.uci.edu", "cs.uci.edu", "informatics.uci.edu", "stat.uci.edu"])): #check domains
            return False
        
        if not url.isascii(): #ensure sending the server a request with an ASCII URL
            return False
        
        if check_repeating_segment(parsed):
            return False

        return not re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower())

    except TypeError:
        print ("TypeError for ", parsed)
        raise

    except IndexError:#test bug
        print("Error for", parsed)
        print("netloc:", parsed.netloc)
        print("split_result:", parsed.netloc.split(".", 1))
        sys.exit()

def checkrobots(url):
    parsed = urlparse(url)
    baseurl = f"{parsed.scheme}://{parsed.netloc}"
    rp = RobotFileParser()
    rp.set_url(urljoin(baseurl, '/robots.txt'))
    try:
        rp.read()
    except Exception:
        return True
    return rp.can_fetch('*', url)

def check_repeating_segment(parsed):
    path = parsed.path
    segment = path.strip("/").split("/")
    segment_set = set(segment)
    if any(segment.count(segment) > 2 for segment in segment_set):
        return True
    return False
    
if __name__ == "__main__":
    url = "https://example.com/路径?query=测试"
    print(is_valid(url))
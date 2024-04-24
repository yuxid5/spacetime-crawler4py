import requests
from bs4 import BeautifulSoup
def get_hashvalue(content): #use this function to calculate hash value
    lisOfAllToken = tokenize(content) #tokenize content
    tokenFrequency = computeWordFrequencies(lisOfAllToken)#compute frequency
    vector = [0] * 64 #initialize vector
    for word, weight in tokenFrequency.items():
        word_hash = hash(word) #compute word hash value
        for i in range(64): #updtate vector
            bitmask = 1 << i
            if word_hash & bitmask:
                vector[i] += weight  # if 1 add weight
            else:
                vector[i] -= weight  # if 0，subtract weight
    fingerprint = 0 #generating fingerprint
    for i in range(64):
        if vector[i] > 0:
            fingerprint |= 1 << i
    return fingerprint

def hamming_distance(hash1, hash2):
    x = hash1 ^ hash2
    total = 0
    while x:
        total += 1
        x &= x - 1
    return total

def similarity_score(hash1, hash2, hash_bits=64):
    distance = hamming_distance(hash1, hash2)
    similarity = (hash_bits - distance) / hash_bits
    return similarity

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
        if item not in wordDict:
            wordDict[item] = 1
        else:
            wordDict[item] +=1
    return wordDict

if __name__ == "__main__":
    # text1 = "This is an example of text for simhash computation."
    # text2 = "y"

    # simhash1 = get_hashvalue(text1)
    # simhash2 = get_hashvalue(text2)
    # reuslt = similarity_score(simhash1,simhash2)
    # print(reuslt)
    # url1 = "https://wics.ics.uci.edu/wics-hosts-a-toy-hacking-workshop-with-dr-garnet-hertz/13-02-03-toy-hacker-008"
    # html_content1 = requests.get(url1).text
    # soup1 = BeautifulSoup(html_content1, 'html.parser')
    # content_hash1 = get_hashvalue(soup1.get_text(separator=' ', strip=True))

    url2 = "https://ics.uci.edu/~yuxid5"
    html_content2 = requests.get(url2).text
    soup2 = BeautifulSoup(html_content2, 'html.parser')
    content_hash2 = get_hashvalue(soup2.get_text(separator=' ', strip=True))
    test1 = get_hashvalue("Hello this is a message from att, and bdw is shit")
    test2 = get_hashvalue("y")
    print("similarity: ", similarity_score(test1, test2))
    print(soup2.get_text(separator=' ', strip=True))
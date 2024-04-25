from bs4 import BeautifulSoup
import requests
import hashlib

visited_hashes = set()

def get_fingerprint(content): #use this function to calculate hash value
    lisOfAllToken = tokenize(content) #tokenize content
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



if __name__ == "__main__":
    #text1 = "x."
    #text2 = "y"

    # simhash1 = get_hashvalue(text1)
    # simhash2 = get_hashvalue(text2)
    url1 = "http://archive.ics.uci.edu/datasets/E.+Coli+Genes"
    url2 = "https://ics.uci.edu/~thornton/ics33/Notes/"
    html_content1 = requests.get(url1).text
    html_content2 = requests.get(url2).text
    soup1 = BeautifulSoup(html_content1, 'html.parser')
    soup2 = BeautifulSoup(html_content2, 'html.parser')
    fig1 = get_fingerprint(soup1.get_text(separator=' ', strip=True))
    fig2 = get_fingerprint(soup2.get_text(separator=' ', strip=True))
    print(get_score(fig1,fig2))
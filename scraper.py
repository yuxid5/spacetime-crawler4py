import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup #this import is used to parsing html
import sys

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
    if resp.status == 200:
        if resp.raw_response is not None: #avoid None
            soup = BeautifulSoup(resp.raw_response.content, 'html.parser') #parse html
            for n_url in soup.find_all('a', href=True):
                if is_valid(n_url['href']):
                    links_collection.append(n_url['href'])
    else:
        passs
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


if __name__ == "__main__":
    url = "https://example.com/路径?query=测试"
    print(is_valid(url))

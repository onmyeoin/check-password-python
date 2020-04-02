import requests
import hashlib
import sys

# sends start of password hash to api
def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check API')
    return res

# check password hash against list of potential pw hashes
def get_password_leak_counts(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


# create hash of pw, split into head and tail to send only first 5 chars of hash to api
# list of hashes that match first 5 chars returned
# pw hash checked against api response
def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    head, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(head)
    return get_password_leak_counts(response, tail)

def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} found {count} times. NOT secure')
        else:
            print(f'{password} is secure')
    return 'done!'

main(sys.argv[1:])

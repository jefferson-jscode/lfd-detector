import sys
import requests
import argparse
from urllib.parse import urlparse


def download_base(url_object):
  query = url_object.query.split('=')[0]
  base = f'{url_object.scheme}://{url_object.netloc}{url_object.path}?{query}='
  return base


def read_file(filename):
  lines = []
  
  with open(filename, 'r') as file:
    lines = file.read().splitlines()

  return lines


def save_file(filename, content):
  open(filename, 'wb').write(content)


def is_vulnerable(response):
  content_disposition = response.headers.get('Content-Disposition')
  if content_disposition is None:
    return False

  has_attachment = content_disposition.find('attachment')

  return has_attachment != -1


def try_download(url_object):
  url = download_base(url_object)
  file_to_try = url_object.path.split('/')[-1]

  response = requests.get(url + file_to_try, allow_redirects=True)
  return response


if __name__ == '__main__':
  parser = argparse.ArgumentParser(description='Check websites for LFD (Local File Download) vulnerability.')
  '''
    Options:
      
      --input: INPUT FILE
      --output: OUTPUT FILE
      --vulnerable: VULNERABLE OUTPUT FILE
      --secure: NOT VULNERABLE OUTPUT FILE

  '''


  urls_to_try = read_file('test_urls.txt')

  for url in urls_to_try:
    url_object = urlparse(url)
    
    try:
      response = try_download(url_object)

      website = url_object.netloc

      if is_vulnerable(response):
        print('Website ' + website + ' is VULNERABLE')
        print('Vulnerable URL:', download_base(url_object))

      else:
        print('Website ' + website + ' is NOT vulnerable')
        print('Vulnerable URL:', download_base(url_object))


    except:
      print('Error checking: ' + url_object.netloc)
    
    print('\n')

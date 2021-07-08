import flask
from flask import Flask
from OpenSSL import SSL
from flask import request
from flask import (Blueprint, current_app, flash, jsonify, redirect, request,url_for)
from cryptography import x509
from cryptography.x509.oid import NameOID
import idna
import pickle
from socket import socket
from collections import namedtuple
import whois
import datetime
import math
import re
import time
import traceback
from IPy import IP
import requests
from bs4 import BeautifulSoup
import pandas as pd
from pathlib import Path
app = Flask(__name__)

regex = re.compile(
        r'^(?:http|ftp)s?://' # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
        r'localhost|' #localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
        r'(?::\d+)?' # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)


def check_at_symbol(s):
  if "@" in s:
    return True
  else:
    return False


def check_if_ip(s):
  try:
    s = s.replace("http://","")
    s = s.replace("https://","")
    if s.find('/')!=-1 :
      index = s.find('/')
      s = s[:index]
    x = IP(s)
    return True
  except:
    return False

def check_hexadecimal_code(s):
  if s.find("%")!=-1:
    return True
  else:
    return False

def check_allowed_url_length(s):
  if len(s)>35:
    return True
  else:
    return False

def check_double_slash_symbol(s):
  if s.count("//")>=2:
    return True
  else:
    return False

h_text = {}
h_cookie = {}

def parse_page_from_url(url):
  # page = urlopen(url)
  # html_bytes = page.read()
  # html = html_bytes.decode("utf-8")
  try:
    response = requests.get(url, verify=False)
    # print(response.text)
    html=response.text
    h_text[url] = html
    h_cookie[url] = response.cookie
  except:
    h_text[url] = None
    h_cookie[url] = None

def check_map(url):
  if url in h_text:
    return True
  else:
    parse_page_from_url(url)
    return True

def return_removed_url(s,j):
  return s.replace("."+j,"")

def remove_domain_extensions_from_url(s):
  url_components = s.split(".")
  for i in range(0,len(url_components)):
    for j in range(0,len(domain_extension_list)):
      # print(i,j)
      if url_components[i]==domain_extension_list[j]:
        return return_removed_url(s,domain_extension_list[j])


def check_domain_name(s):
  if s.count("https://")==0:
    s = "https://"+s
  if check_map(s):
    html = h_text[s]
    if html ==None:
      return False
    s_after = remove_domain_extensions_from_url(s)
    # print("s",s)
    if s_after == None:
      # print(s)
      return False
    sa = s_after.split(".")

    for i in range(0,len(sa)):
      if html.find(sa[i])!=-1:
        return True
    return False
  else:
    raise ValueError('Parse Page First')


def check_prefix(s):
  return check_domain_name(s)

def check_form(url):
  try:
    if url.count('http://')<=0:
      url = "http://"+url
    check_map(url)
    html = h_text[url]
    soup = BeautifulSoup(html, 'html.parser')
    urls = []
    for link in soup.find_all('form'):
        # link.get('href')
        return True
    return False
  except:
    return False

#READ FROM CSV TO PANDAS DF
domain_extension_list_df = pd.read_csv("domain_extension_list.csv")


domain_extension_list = []
for i in domain_extension_list_df.itertuples():
  # print(i[1])
  domain_extension_list.append(i[1])

famous_url_shorteners = ["goo.gl", "bit.ly", "owl.ly", "deck.ly", "bl.ink"]


# abnormal url shortening
def abnormal_url_shortening(url):
  for i in range(0, len(domain_extension_list)):
    # print(domain_extension_list[i])
    dom = str(domain_extension_list[i])

    if url.find(dom) != -1:
      return False
  # print("completed level 1")
  for i in range(0, len(famous_url_shorteners)):
    if url.find(famous_url_shorteners[i]) != -1:
      return False
  return True


def get_all_links_from_url(url):
  reqs = requests.get(url)
  soup = BeautifulSoup(reqs.text, 'html.parser')

  urls = []
  for link in soup.find_all('a'):
    print(link.get('href'))
    urls.append(link.get('href'))


known_extensions = ["mp4", "m4a", "m4v", "f4v", "f4a", "m4b", "m4r", "f4b", "mov", "3gp", "3gp", "3g2", "3gpp", "mp3",
                    "png", "jpg", "bmp"]


def check_malicious_software_download_extension(url):
  try:
    if url.count("http://") == 0:
      url = "http://" + url
    check_map(url)
    html = h_text[url]
    soup = BeautifulSoup(html, 'html.parser')

    urls = []
    for link in soup.find_all('a'):
      # print(link.get('href'))
      urls.append(link.get('href'))
      v = link.get('href')
      extension = v.split('.')[-1]
      if len(extension) == 3:
        pass
        if extension in known_extensions:
          return False
        else:
          return True
      else:
        return False
  except:
    return False

ext=['com', 'uk', 'ac_uk', 'ar', 'at', 'pl', 'be', 'biz', 'br', 'ca', 'cc', 'cl', 'club', 'cn', 'co', 'jp', 'co_jp', 'cz', 'de', 'store', 'download', 'edu', 'education', 'eu', 'fi', 'fr', 'id', 'in_', 'info', 'io', 'ir', 'is_is', 'it', 'kr', 'kz', 'lt', 'ru', 'lv', 'me', 'mobi', 'mx', 'name', 'net', 'ninja', 'se', 'nu', 'nyc', 'nz', 'online', 'org', 'pharmacy', 'press', 'pw', 'rest', 'ru_rf', 'security', 'sh', 'site', 'space', 'tech', 'tel', 'theatre', 'tickets', 'tv', 'us', 'uz', 'video', 'website', 'wiki', 'xyz']

h_whois = {}


def check_whois_map(url):
  if url in h_whois:
    return h_whois[url]
  else:
    try:
      # do stuff
      domain = whois.query(url)
      h_whois[url] = domain
    except:
      domain = None
      h_whois[url] = domain
    return domain


def getAge(url):
  url= url.replace("http://","")
  url= url.replace("https://","")
  for i in ext:
    #print(i)
    if url.find(i)!=-1:
      url=url.split('.'+i,1)
      url=url[0]
      url=url+'.'+i
      # print(url)
      break
  domain=check_whois_map(url)
  if domain!=None:
    creationdate=domain.creation_date
    today_Date=datetime.datetime.today()
    day=today_Date.day-creationdate.day
    month=today_Date.month-creationdate.month
    year=today_Date.year-creationdate.year
    age=(year*365)+(month*30)+day
    age=age/365
#     print('age',age)
    return math.floor(age)
  else:
#     print('age',0)
    return 0


def check_age(url):
  try:
    if url.count('http://') == 1:
      url = "http://" + url
    age = getAge(url)
    if age < 1:
      # print(url,age)
      return True
    else:
      # print(url,age)
      return False

  except:
    return True



def is_blacklisted(url):
  url= url.replace("http://","")
  url= url.replace("https://","")
  for i in ext:
    #print(i)
    if url.find(i)!=-1:
      url=url.split('.'+i,1)
      url=url[0]
      url=url+'.'+i
      # print(url)
      break
  domain=check_whois_map(url)
  if domain!=None:
    return False
  else:
    return True

HostInfo = namedtuple(field_names='cert hostname peername', typename='HostInfo')

def get_certificate(hostname, port):
    hostname_idna = idna.encode(hostname)
    sock = socket()

    sock.connect((hostname, port))
    peername = sock.getpeername()
    ctx = SSL.Context(SSL.SSLv23_METHOD) # most compatible
    ctx.check_hostname = False
    ctx.verify_mode = SSL.VERIFY_NONE

    sock_ssl = SSL.Connection(ctx, sock)
    sock_ssl.set_connect_state()
    sock_ssl.set_tlsext_host_name(hostname_idna)
    sock_ssl.do_handshake()
    cert = sock_ssl.get_peer_certificate()
    crypto_cert = cert.to_cryptography()
    sock_ssl.close()
    sock.close()

    return HostInfo(cert=crypto_cert, peername=peername, hostname=hostname)

h_ssl_map = {}
def check_if_self_signed_ssl(url):
  if url in h_ssl_map:
    return h_ssl_map[url]
  try:
    # print(url)
    url = url.replace("http://","").replace("https://","").replace("/","")
    cert = get_certificate(url,443)
    if cert.cert.issuer == cert.cert.subject:
      h_ssl_map[url] = True
      return True
    else:
      h_ssl_map[url] = False
      return False
  except:
    h_ssl_map[url] = False
    return False

def check_abnormal_cookie_domain(url):
  try:
    if url.count('http://')<=0:
      url = "http://" + url
    check_map(url)
    p = h_cookie[url]
    # print(p)
    p = str(p)
    # print(p)
    s2 = p.find('for .')
    # print(s2)
    s3 = p.find('/', s2)
    # print(s3)
    p2 = p[s2+5:s3]
    # print(p2)
    if p2 in url:
      return False
    else:
      return True
  except:
    return False

def normalise(value):
  if value == True:
    return 1
  else:
    return 0


def match_port(url):
  for word in url.split(':'):
   if word.isdigit():
      if word!=80:
        return True
  return False


path = Path()
filename = 'cybersecuritymodel.sav'
loaded_model = pickle.load(open(path/filename, 'rb'))


def get_features(x):
  f1 = normalise(check_at_symbol(x))
  f2 = normalise(check_if_ip(x))
  f3 = normalise(check_hexadecimal_code(x))
  f4 = normalise(check_allowed_url_length(x))
  f5 = normalise(check_double_slash_symbol(x))
  f6 = normalise(check_domain_name(x))
  f7 = normalise(check_prefix(x))
  f8 = normalise(check_form(x))
  f9 = normalise(abnormal_url_shortening(x))
  f10 = normalise(check_malicious_software_download_extension(x))
  f11 = normalise(check_abnormal_cookie_domain(x))
  f12 = normalise(check_age(x))
  f13 = normalise(match_port(x))
  f14 = normalise(check_if_self_signed_ssl(x))
  f15 = normalise(is_blacklisted(x))
  lis = []
  lis2 = []
  lis2.extend([f1, f2, f3, f4, f5, f6, f7, f8, f9, f10, f11, f12, f13, f14, f15])
  lis.append(lis2)
  return lis


@app.route('/route')
def hello_world():
  url = request.args.get('url', default="", type=str)

  try:
    # response = requests.get(url,verify = False)
    print("URL is valid and exists on the internet")
    lis = get_features(url)
    # print(lis)
    res = loaded_model.predict(lis)
    print(res)
    if res[-1] == 0:
      response = flask.jsonify({'some': "benign"})
      response.headers.add('Access-Control-Allow-Origin', '*')
      return response
    else:

      response = flask.jsonify({'some': 'phish'})
      response.headers.add('Access-Control-Allow-Origin', '*')
      return response
  except requests.ConnectionError as exception:
    print("URL does not exist on Internet")

  response = flask.jsonify({'some': 'exception'})
  response.headers.add('Access-Control-Allow-Origin', '*')
  return response

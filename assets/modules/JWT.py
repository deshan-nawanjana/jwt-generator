import json
import time
import base64
import hmac
import hashlib

PRIVATE_KEY = 'my_site_secret'

def base64Encode(text) :
  text = base64.b64encode(text.encode("ascii"))
  text = text.decode().rstrip().lstrip()
  text = text.replace('+', '-')
  text = text.replace('/', '_')
  text = text.replace('=', '')
  return text

def generateToken(object, duration) :
  global PRIVATE_KEY
  # header data
  header = json.dumps({ "alg" : "HS256", "type" : "JWT" })
  # payload data
  payload = json.dumps({
    "iat" : time.time(),
    "exp" : time.time() + duration / 1000,
    "obj" : json.dumps(object)
  })
  # create encoded header
  header64 = base64Encode(header)
  # create encoded payload
  payload64 = base64Encode(payload)
  # create signature
  signature = hmac.new(
    bytes(PRIVATE_KEY, 'UTF-8'),
    (header64 + "." + payload64).encode(),
    hashlib.sha256
  ).hexdigest()
  # encode signature
  signature64 = base64Encode(signature)
  # return token
  return header64 + "." + payload64 + "." + signature64

def validateToken(token) :
  global PRIVATE_KEY
  # get token string and split
  if token.find("Bearer ") == 0 :
    token = token[7:]
  parts = token.split(".")
  # define three parts
  header64 = parts[0]
  payload64 = parts[1]
  signature64 = parts[2]
  # create signature again from received header and payload
  check = hmac.new(
    bytes(PRIVATE_KEY, 'UTF-8'),
    (header64 + "." + payload64).encode(),
    hashlib.sha256
  ).hexdigest()
  # check if token decodable
  if base64Encode(check) != signature64 :
    return 'TOKEN_INVALID'
  # get payload data if token decoded successfully
  payload = json.loads(base64.b64decode(payload64 + '=='))
  # check token values
  if "iat" not in payload :
    # no issued time
    return 'TOKEN_INVALID'
  elif "exp" not in payload :
    # no expiration time
    return 'TOKEN_INVALID'
  elif "obj" not in payload :
    # no expiration time
    return 'TOKEN_INVALID'
  elif float(payload["iat"]) > time.time() or float(payload["exp"]) < time.time() :
    # expired token
    return 'TOKEN_EXPIRED'
  else :
    # return valid token
    return json.loads(payload["obj"])

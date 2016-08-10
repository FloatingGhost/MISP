#!/usr/bin/env python3

#Convert MISP JSON to Arcsight's Common Event Format
import json
import sys

CEF_VERSION = 0
DEV_VENDOR  = "MISP"
DEV_PRODUCT = "MISP"
DEV_VERSION = "2.4.49"

def loadEvent(path):
  return json.load(path)["response"][0]

def generateHeader(event_id, event_name):
  hdr = "CEF:{}|{}|{}|{}|{}|{}|1|".format(
          CEF_VERSION, DEV_VENDOR, DEV_PRODUCT, DEV_VERSION,
          event_id, event_name
        )
  return hdr

def ishash(cat):
  if "md5" in cat:
    return True
  if "sha" in cat:
    return True
  return False

def generateExtension(hdr, attributes):
  ext = ""
  for attr in attributes:
    a = hdr
    cat = attr["category"]
    if cat == "Network activity":
      if "dst" in attr["type"]:
        a += "dst={} ".format(attr["value"])
      if "src" in attr["type"]:
        a += "src={} ".format(attr["value"])
      if ishash(attr["type"]):
        a += "fileHash={} ".format(attr["value"])

    if a != hdr:
      ext += "{}\n".format(a)
  return ext

if __name__ == "__main__":
  event = loadEvent(open(sys.argv[1], "r"))
  
  hdr = generateHeader(event["Event"]["id"], event["Event"]["info"])
  output = generateExtension(hdr, event["Event"]["Attribute"])
  print(output)

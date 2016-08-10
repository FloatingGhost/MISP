#!/usr/bin/env python

#A script to convert from a STIX file
#(json or XML)
#and create a MISP JSON from it

##USAGE:

#stix2misp.py [input_file] [output_file]

from stix.core import STIXPackage, STIXHeader
import stix
import json
import sys
import time

def buildObservable(o):
  return {"category":"Network activity", 
          "type":"ip-src",
          "value":"192.168.1.1",
          "comment":"A test attribute"
        }

if __name__ == "__main__":
  upload_file = open(sys.argv[1], "r")

  stix_data = None 
  
  #Convert it to a package
  try:
    stix_data = STIXPackage().from_xml(upload_file)
  except Exception as e1:
    #Maybe a json?
    try:
      stix_data = STIXPackage().from_json(upload_file)
    except Exception as e2:
      #We can't make head nor tail of it
      print(json.dumps({"result":0, 
                     "msg":"Could not decode STIX File\n{},{}".format(e1,e2)})) 
      sys.exit(1)

  if stix_data == None:
    #If something went terribly wrong and somehow it failed
    print(json.dumps({"result":0, "msg":"Could not decode STIX File"}))
    sys.exit(1)

  print("Decoded...")

  #If the package didn't have a header, it's useful to have one
  if not stix_data.stix_header:
    stix_data.stix_header = STIXHeader()

  #Give it a title
  if not stix_data.stix_header.title:
    stix_data.stix_Header.title = "STIX Import -- {}".format(
                    time.strftime("%x"))

  print("Header set...") 

  event = {
            "Event" : 
             {
              "risk": "0",
              "info": "Test event",
              "distribution":"0",
              "analysis": "0",
              "Attribute": [],
             },
           }


  if stix_data.observables:
    for i in stix_data.observables:
      event["Event"]["Attribute"].append(buildObservable(i))
  event["Event"]["Attribute"].append(buildObservable(None))
  with open(sys.argv[2], "w") as f:
    f.write(json.dumps({"response":[event]}))
  print("DONE!")

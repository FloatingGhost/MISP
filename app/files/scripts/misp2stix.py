import sys
import json
import uuid
import os
import time
import re
import datetime
from misp2cybox import *
from misp2ciq import *
from dateutil.tz import tzutc
from stix.indicator import Indicator
from stix.indicator.valid_time import ValidTime
from stix.ttp import TTP, Behavior
from stix.ttp.malware_instance import MalwareInstance
from stix.incident import Incident, Time, ImpactAssessment, ExternalID, AffectedAsset
from stix.exploit_target import ExploitTarget, Vulnerability
from stix.incident.history import JournalEntry, History, HistoryItem
from stix.threat_actor import ThreatActor
from stix.core import STIXPackage, STIXHeader
from stix.common import InformationSource, Identity, Confidence
from stix.data_marking import Marking, MarkingSpecification
from stix.extensions.marking.tlp import TLPMarkingStructure
from stix.common.related import *
from stix.common.confidence import Confidence
from stix.common.vocabs import IncidentStatus
import cybox
from mixbox import idgen
from mixbox.namespaces import Namespace
from cybox.objects.address_object import Address

#####################################
#STIX PACKAGE STRUCTURE
#
#ONE FOR EACH MISP EVENT
#
#PACKAGE
#  - HEADER
#    - TITLE
#  - INDICATORS
#    - RELATED OBSERVABLES
#  - TTPS
#  - OBSERVABLES
###################################

namespace = ["MISP", 'https://github.com/MISP/MISP']

NS_DICT_TMP = {
    "http://cybox.mitre.org/common-2": 'cyboxCommon',
    "http://cybox.mitre.org/cybox-2": 'cybox',
    "http://cybox.mitre.org/default_vocabularies-2": 'cyboxVocabs',
    "http://cybox.mitre.org/objects#ASObject-1": 'ASObj',
    "http://cybox.mitre.org/objects#AddressObject-2": 'AddressObj',
    "http://cybox.mitre.org/object#ArtifactObject":"ArtifactObj",
    "http://cybox.mitre.org/objects#DomainNameObject-1": 'DomainNameObj',
    "http://cybox.mitre.org/objects#EmailMessageObject-2":
    'EmailMessageObj',
    "http://cybox.mitre.org/objects#FileObject-2": 'FileObj',
    "http://cybox.mitre.org/objects#HTTPSessionObject-2": 'HTTPSessionObj',
    "http://cybox.mitre.org/objects#HostnameObject-1": 'HostnameObj',
    "http://cybox.mitre.org/objects#MutexObject-2": 'MutexObj',
    "http://cybox.mitre.org/objects#PipeObject-2": 'PipeObj',
    "http://cybox.mitre.org/objects#URIObject-2": 'URIObj',
    "http://cybox.mitre.org/objects#WinRegistryKeyObject-2":
    'WinRegistryKeyObj',
    "http://data-marking.mitre.org/Marking-1": 'marking',
    "http://data-marking.mitre.org/extensions/MarkingStructure#TLP-1":
    'tlpMarking',
    "http://stix.mitre.org/ExploitTarget-1": 'et',
    "http://stix.mitre.org/Incident-1": 'incident',
    "http://stix.mitre.org/Indicator-2": 'indicator',
    "http://stix.mitre.org/TTP-1": 'ttp',
    "http://stix.mitre.org/ThreatActor-1": 'ta',
    "http://stix.mitre.org/common-1": 'stixCommon',
    "http://stix.mitre.org/default_vocabularies-1": 'stixVocabs',
    "http://stix.mitre.org/extensions/Identity#CIQIdentity3.0-1":
    'stix-ciqidentity',
    "http://stix.mitre.org/extensions/TestMechanism#Snort-1": 'snortTM',
    "http://stix.mitre.org/stix-1": 'stix',
    "http://www.w3.org/2001/XMLSchema-instance": 'xsi',
    "urn:oasis:names:tc:ciq:xal:3": 'xal',
    "urn:oasis:names:tc:ciq:xnl:3": 'xnl',
    "urn:oasis:names:tc:ciq:xpil:3": 'xpil',
}

NS_DICT = {}
for key in NS_DICT_TMP.keys():
  if "http" in key or "urn" in key:
    NS_DICT[NS_DICT_TMP[key]] = key
  else:
    NS_DICT[key] = NS_DICT_TMP[key]
SCHEMALOC_DICT = {
    'http://cybox.mitre.org/common-2':
    'http://cybox.mitre.org/XMLSchema/common/2.1/cybox_common.xsd',
    'http://cybox.mitre.org/cybox-2':
    'http://cybox.mitre.org/XMLSchema/core/2.1/cybox_core.xsd',
    'http://cybox.mitre.org/default_vocabularies-2':
    'http://cybox.mitre.org/XMLSchema/default_vocabularies/2.1/cybox_default_vocabularies.xsd',
    'http://cybox.mitre.org/objects#ASObject-1':
    'http://cybox.mitre.org/XMLSchema/objects/AS/1.0/AS_Object.xsd',
    'http://cybox.mitre.org/objects#AddressObject-2':
    'http://cybox.mitre.org/XMLSchema/objects/Address/2.1/Address_Object.xsd',
    'http://cybox.mitre.org/objects#DomainNameObject-1':
    'http://cybox.mitre.org/XMLSchema/objects/Domain_Name/1.0/Domain_Name_Object.xsd',
    'http://cybox.mitre.org/objects#EmailMessageObject-2':
    'http://cybox.mitre.org/XMLSchema/objects/Email_Message/2.1/Email_Message_Object.xsd',
    'http://cybox.mitre.org/objects#FileObject-2':
    'http://cybox.mitre.org/XMLSchema/objects/File/2.1/File_Object.xsd',
    'http://cybox.mitre.org/objects#HTTPSessionObject-2':
    'http://cybox.mitre.org/XMLSchema/objects/HTTP_Session/2.1/HTTP_Session_Object.xsd',
    'http://cybox.mitre.org/objects#HostnameObject-1':
    'http://cybox.mitre.org/XMLSchema/objects/Hostname/1.0/Hostname_Object.xsd',
    'http://cybox.mitre.org/objects#MutexObject-2':
    'http://cybox.mitre.org/XMLSchema/objects/Mutex/2.1/Mutex_Object.xsd',
    'http://cybox.mitre.org/objects#PipeObject-2':
    'http://cybox.mitre.org/XMLSchema/objects/Pipe/2.1/Pipe_Object.xsd',
    'http://cybox.mitre.org/objects#URIObject-2':
    'http://cybox.mitre.org/XMLSchema/objects/URI/2.1/URI_Object.xsd',
    'http://cybox.mitre.org/objects#WinRegistryKeyObject-2':
    'http://cybox.mitre.org/XMLSchema/objects/Win_Registry_Key/2.1/Win_Registry_Key_Object.xsd',
    'http://data-marking.mitre.org/Marking-1':
    'http://stix.mitre.org/XMLSchema/data_marking/1.1.1/data_marking.xsd',
    'http://data-marking.mitre.org/extensions/MarkingStructure#TLP-1':
    'http://stix.mitre.org/XMLSchema/extensions/marking/tlp/1.1.1/tlp_marking.xsd',
    'http://stix.mitre.org/ExploitTarget-1':
    'http://stix.mitre.org/XMLSchema/exploit_target/1.1.1/exploit_target.xsd',
    'http://stix.mitre.org/Incident-1':
    'http://stix.mitre.org/XMLSchema/incident/1.1.1/incident.xsd',
    'http://stix.mitre.org/Indicator-2':
    'http://stix.mitre.org/XMLSchema/indicator/2.1.1/indicator.xsd',
    'http://stix.mitre.org/TTP-1':
    'http://stix.mitre.org/XMLSchema/ttp/1.1.1/ttp.xsd',
    'http://stix.mitre.org/ThreatActor-1':
    'http://stix.mitre.org/XMLSchema/threat_actor/1.1.1/threat_actor.xsd',
    'http://stix.mitre.org/common-1':
    'http://stix.mitre.org/XMLSchema/common/1.1.1/stix_common.xsd',
    'http://stix.mitre.org/default_vocabularies-1':
    'http://stix.mitre.org/XMLSchema/default_vocabularies/1.1.1/stix_default_vocabularies.xsd',
    'http://stix.mitre.org/extensions/Identity#CIQIdentity3.0-1':
    'http://stix.mitre.org/XMLSchema/extensions/identity/ciq_3.0/1.1.1/ciq_3.0_identity.xsd',
    'http://stix.mitre.org/extensions/TestMechanism#Snort-1':
    'http://stix.mitre.org/XMLSchema/extensions/test_mechanism/snort/1.1.1/snort_test_mechanism.xsd',
    'http://stix.mitre.org/stix-1':
    'http://stix.mitre.org/XMLSchema/core/1.1.1/stix_core.xsd',
    'urn:oasis:names:tc:ciq:xal:3':
    'http://stix.mitre.org/XMLSchema/external/oasis_ciq_3.0/xAL.xsd',
    'urn:oasis:names:tc:ciq:xnl:3':
    'http://stix.mitre.org/XMLSchema/external/oasis_ciq_3.0/xNL.xsd',
    'urn:oasis:names:tc:ciq:xpil:3':
    'http://stix.mitre.org/XMLSchema/external/oasis_ciq_3.0/xPIL.xsd',
}

# mappings
status_mapping = {'0': 'New', '1': 'Open', '2': 'Closed'}
TLP_mapping = {'0': 'AMBER', '1': 'GREEN', '2': 'GREEN', '3': 'GREEN'}
confidence_mapping = {False: 'None', True: 'High'}

not_implemented_attributes = [
    'yara',
    'pattern-in-traffic',
    'pattern-in-memory']

non_indicator_attributes = ['text', 'comment', 'other', 'link', 'target-user',
                            'target-email', 'target-machine', 'target-org',
                            'target-location', 'target-external',
                            'email-target', 'vulnerability', 'attachment']

# Load the array from MISP. MISP will call this script with a parameter
# containing the temporary file it creates for the export
#(using a generated 12 char alphanumeric name)


def loadEvent(args, pathname):
    try:
        filename = pathname + "/tmp/" + args[1]
        print(filename)
        # filename = "tmp/" + args[1]
        tempFile = open(filename, 'r')
        events = json.loads(tempFile.read())
        print("Loaded sucesfully")
        return events
    except Exception as ex:
        print((json.dumps(
            {'success': 0,
                 'message': 'The temporary MISP export file could not be read'
             }
        )))
        sys.exit(1)


def saveFile(args, pathname, package):
    try:
        if isinstance(package, STIXPackage):
          package = [package]
        for i in range(len(package)):
          p = package[i]
          filename = pathname + "/tmp/" + args[1] + str(i) + ".out"
          # filename = "test.out"
          with open(filename, 'w') as f:
              if args[2] == 'json':
                  f.write(p.to_json())
              else:
                  towrite = str(p.to_xml(
                                         auto_namespace=False,
                                         ns_dict=NS_DICT,
                                         schemaloc_dict=SCHEMALOC_DICT
                                        ), 
                                'utf-8'
                               )
                  #urlre = re.compile("\:[hu][^\"]*\=\"")
                  #for i in urlre.findall(towrite):
                  #  print(i[1:-2])
                  #  towrite = towrite.replace(i[1:-2], '"{}"'.format(i[1:-2]))
                  f.write(towrite)
    except Exception as ex:
        print(ex)
        print((json.dumps(
              {'success': 0,
                          'message': 'The STIX file could not be written'
               }
              )
              ))
        sys.exit(1)

# generate a package that will contain all of the event-packages


def generateMainPackage():
    stix_package = STIXPackage()
    stix_header = STIXHeader()
    stix_header.title = "Export from " + namespace[1] + " MISP"
    #stix_header.package_intents = "Threat Report"
    stix_package.stix_header = stix_header
    return stix_package

# generate a package for each event

def addToPackage(pkg, event):
  try:
    q = iter(event)
    for i in q:
      addToPackage(pkg, event)
  except TypeError:
    pkg.add(event)

def generateEventPackage(event):
    if isinstance(event, dict):
      
      #A unique ID for the package
      package_name = "{}:STIXPackage-{}".format(
                                                 namespace[1],
                                                 event["Event"]["uuid"]
                                                )
      
      #MISP gives us a nice little timestamp to use
      timestamp = getDateFromTimestamp(int(event["Event"]["timestamp"]))

      #Generate a new package
      stix_package = STIXPackage(id_=package_name, timestamp=timestamp)
      
      #Name it, make sure we keep the MISP id for future reference
      stix_header = STIXHeader()
      stix_header.title = "{} (MISP Event {})".format(event["Event"]["info"],
                                                  event["Event"]["id"]
                                                    )

      stix_package.stix_header = stix_header
      
      #Grab the STIX objects from the MISP json
      objects = generateSTIXObjects(event)

      for i in objects:
        addToPackage(stix_package, i)
      return stix_package

# generate the incident information. MISP events are currently mapped to
# incidents with the event metadata being stored in the incident information
def getFullName(t):
  names = {"ipdst":"IP Destination", "ipsrc":"IP Source", "domain":"Domain Name"}
  return names[t] or ""
def generateSTIXObjects(event):
    print((list(event["Event"].keys())))
    event_id = "{}:indicator-{}".format(namespace[1], event["Event"]["uuid"])
    print("ID "+ str(event_id))
    objects = []
    for obj in event["Event"]["Attribute"]:
      type_ = obj["type"]
      print("{} HAS KEYS {}".format(type_, obj.keys()))
      if type_ == "threat-actor":
        print("Adding Threat Actor {}".format(obj["value"]))
        objects.append(ThreatActor(title=obj["value"], description=obj["comment"]))
      elif type_ in ["domain", "ipdst", "ipsrc", "url"]:
        obs = (Observable(Address(address_value=obj["value"]), 
              title=obj["comment"] or getFullName(type_) + ": " + obj["value"]))
        if obj["comment"]:
          #We can probably add an indicator
          ind = (Indicator(title=obj["comment"]))
          obs_ind = Observable(idref=obs.id_)
          obs_ind.id_ = None
          ind.add_observable(obs_ind)
          objects.append(obs_ind)
          objects.append(ind)
        objects.append(obs)
    return objects

# set up the dates for the incident
def setDates(incident, date, published):
    timestamp = getDateFromTimestamp(published)
    incident.timestamp = timestamp
    incident_time = Time()
    incident_time.incident_discovery = convertToStixDate(date)
    incident_time.incident_reported = timestamp
    incident.time = incident_time

# decide what to do with the attribute, as not all of them will become
# indicators


def resolveAttributes(incident, ttps, attributes):
    for attribute in attributes:
        if (attribute["type"] in not_implemented_attributes):
            addJournalEntry(
                incident,
                "!Not implemented attribute category/type combination caught! attribute[" + attribute[
                    "category"] + "][" + attribute[
                        "type"] + "]: " + attribute[
                            "value"])
        elif (attribute["type"] in non_indicator_attributes):
            # types that will definitely not become indicators
            handleNonIndicatorAttribute(incident, ttps, attribute)
        else:
            # types that may become indicators
            handleIndicatorAttribute(incident, ttps, attribute)
    for rindicator in incident.related_indicators:
        for ttp in ttps:
            ittp = TTP(idref=ttp.id_, timestamp=ttp.timestamp)
            rindicator.item.add_indicated_ttp(ittp)
    return [incident, ttps]

# Create the indicator and pass the attribute further for observable creation
# This can be called from resolveattributes directly
# Or from handleNonindicatorAttribute, for some special cases


def handleIndicatorAttribute(incident, ttps, attribute):
    indicator = generateIndicator(attribute)
    indicator.add_indicator_type("Malware Artifacts")
    indicator.add_valid_time_position(ValidTime())
    if attribute["type"] == "email-attachment":
        indicator.add_indicator_type("Malicious E-mail")
        generateEmailAttachmentObject(indicator, attribute)
    else:
        generateObservable(indicator, attribute)
    if "data" in attribute:
        if attribute["type"] == "malware-sample":
            createArtifactObject(indicator, attribute)
    relatedIndicator = RelatedIndicator(
                            indicator, relationship=attribute["category"]
                                        )
    incident.related_indicators.append(relatedIndicator)

# Handle the attributes that do not fit into an indicator


def handleNonIndicatorAttribute(incident, ttps, attribute):
    if attribute["type"] in ("comment", "text", "other"):
        if attribute["category"] == "Payload type":
            generateTTP(incident, attribute, ttps)
        elif attribute["category"] == "Attribution":
            ta = generateThreatActor(attribute)
            rta = RelatedThreatActor(ta, relationship="Attribution")
            incident.attributed_threat_actors.append(rta)
        else:
            entry_line = "attribute[" + attribute[
                "category"] + "][" + attribute[
                    "type"] + "]: " + attribute[
                        "value"]
            addJournalEntry(incident, entry_line)
    elif attribute["type"] == "target-machine":
        aa = AffectedAsset()
        if attribute["comment"] != "":
            aa.description = attribute[
                "value"] + " (" + attribute["comment"] + ")"
        else:
            aa.description = attribute["value"]
        incident.affected_assets.append(aa)
    elif attribute["type"] == "vulnerability":
        generateTTP(incident, attribute, ttps)
    elif attribute["type"] == "link":
        if attribute["category"] == "Payload delivery":
            handleIndicatorAttribute(incident, ttps, attribute)
        else:
            addReference(incident, attribute["value"])
    elif attribute["type"].startswith('target-'):
        resolveIdentityAttribute(incident, attribute, namespace[1])
    elif attribute["type"] == "attachment":
        observable = returnAttachmentComposition(attribute)
        related_observable = RelatedObservable(
            observable,
            relationship=attribute["category"])
        incident.related_observables.append(related_observable)
    return [incident, ttps]

# TTPs are only used to describe malware names currently (attribute with
# category Payload Type and type text/comment/other)


def generateTTP(incident, attribute, ttps):
    ttp = TTP(timestamp=getDateFromTimestamp(int(attribute["timestamp"])))
    ttp.id_ = namespace[1] + ":ttp-" + attribute["uuid"]
    setTLP(ttp, attribute["distribution"])
    ttp.title = attribute["category"] + ": " + attribute[
        "value"] + " (MISP Attribute #" + attribute["id"] + ")"
    if attribute["type"] == "vulnerability":
        vulnerability = Vulnerability()
        vulnerability.cve_id = attribute["value"]
        et = ExploitTarget(
            timestamp=getDateFromTimestamp(int(attribute["timestamp"])))
        et.id_ = namespace[1] + ":et-" + attribute["uuid"]
        if attribute["comment"] != "" and attribute["comment"] != "Imported via the freetext import.":
            et.title = attribute["comment"]
        else:
            et.title = "Vulnerability " + attribute["value"]
        et.add_vulnerability(vulnerability)
        ttp.exploit_targets.append(et)
    else:
        malware = MalwareInstance()
        malware.add_name(attribute["value"])
        ttp.behavior = Behavior()
        ttp.behavior.add_malware_instance(malware)
    if attribute["comment"] != "":
        ttp.description = attribute["comment"]
    ttps.append(ttp)
    rttp = TTP(idref=ttp.id_, timestamp=ttp.timestamp)
    relatedTTP = RelatedTTP(rttp, relationship=attribute["category"])
    incident.leveraged_ttps.append(relatedTTP)

# Threat actors are currently only used for the category:attribution
# type:(text|comment|other) attributes


def generateThreatActor(attribute):
    ta = ThreatActor(timestamp=getDateFromTimestamp(
                                                    int(attribute["timestamp"])
    )
                    )
    ta.id_ = namespace[1] + ":threatactor-" + attribute["uuid"]
    ta.title = "{}: (MISP Attribute {})".format(
                                                attribute["category"],
                                                attribute["value"],
                                                attribute["id"]
    )
    if attribute["comment"] != "":
        ta.description = attribute["value"] + " (" + attribute["comment"] + ")"
    else:
        ta.description = attribute["value"]
    return ta

# generate the indicator and add the relevant information


def generateIndicator(attribute):
    indicator = Indicator(
        timestamp=getDateFromTimestamp(int(attribute["timestamp"])))
    indicator.id_ = namespace[1] + ":indicator-" + attribute["uuid"]
    if attribute["comment"] != "":
        indicator.description = attribute["comment"]
    setTLP(indicator, attribute["distribution"])
    indicator.title = attribute["category"] + ": " + attribute[
        "value"] + " (MISP Attribute #" + attribute["id"] + ")"
    indicator.description = indicator.title
    confidence_description = "Derived from MISP's IDS flag."
    confidence_description+= " If an attribute is marked for IDS exports,"
    confidence_description+= " the confidence will be high, otherwise none"
    confidence_value = confidence_mapping.get(attribute["to_ids"], None)
    if confidence_value is None:
        return indicator
    indicator.confidence = Confidence(
        value=confidence_value,
        description=confidence_description,
        timestamp=getDateFromTimestamp(int(attribute["timestamp"])))
    return indicator

# converts timestamp to the format used by STIX


def getDateFromTimestamp(timestamp):
    return datetime.datetime.fromtimestamp(timestamp).isoformat() + "+00:00"

# converts a date (YYYY-mm-dd) to the format used by stix


def convertToStixDate(date):
    return getDateFromTimestamp(time.mktime(datetime.datetime.strptime(date, "%Y-%m-%d").timetuple()))

# takes an object and adds the passed organisation as the
# information_source.identity to it.


def setOrg(target, org):
    ident = Identity(name=org)
    information_source = InformationSource(identity=ident)
    target.information_source = information_source

# takes an object and adds the passed tags as journal entries to it.


def setTag(target, tags):
    for tag in tags:
        addJournalEntry(target, "MISP Tag: " + tag["name"])


def addReference(target, reference):
    if hasattr(target.information_source, "references"):
        target.information_source.add_reference(reference)

# takes an object and applies a TLP marking based on the distribution
# passed along to it


def setTLP(target, distribution):
    marking_specification = MarkingSpecification()
    marking_specification.controlled_structure = "../../../descendant-or-self::node()"
    tlp = TLPMarkingStructure()
    colour = TLP_mapping.get(distribution, None)
    if colour is None:
        return target
    tlp.color = colour
    marking_specification.marking_structures.append(tlp)
    handling = Marking()
    handling.add_marking(marking_specification)
    target.handling = handling

# add a journal entry to an incident


def addJournalEntry(incident, entry_line):
    hi = HistoryItem()
    hi.journal_entry = entry_line
    incident.history.append(hi)

# main


def main(args):
    pathname = os.path.dirname(sys.argv[0])
    if len(sys.argv) > 3:
        namespace[0] = sys.argv[3]
    if len(sys.argv) > 4:
        namespace[1] = sys.argv[4].replace(" ", "_")
    NS_DICT[namespace[0]] = namespace[1]
    #idgen.set_id_namespace((Namespace(namespace[0], namespace[1]), "idk"))
    #idgen.set_id_namespace({namespace[0]: namespace[1]})
    events = loadEvent(args, pathname)
    #If we've only 1 package
    if isinstance(events, dict):
      events = [events]
    #Return one package per event
    #Because that's MUCH nicer to deal with
    packages = []
    #Old way
    #stix_package = generateMainPackage()
    for event in events:
        sub_package = generateEventPackage(event)
        packages.append(sub_package)
 
        packages.append(sub_package)
    saveFile(args, pathname, packages)
    print((json.dumps({'success': 1, 'message': ''})))

if __name__ == "__main__":
    main(sys.argv)

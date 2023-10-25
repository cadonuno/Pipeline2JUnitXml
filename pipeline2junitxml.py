import sys
import json
import argparse
import xml.etree.ElementTree as ET
import traceback
#
# 
#
modules={}
flaws={}
testCaseTree={"findings": None, "children": {}}
#
# Setup CLI Parser
#
parser = argparse.ArgumentParser(description='Accept flags from CLI')
parser.add_argument('-f', action="store", dest="f", help="Pass the filename of the pipeline scan json file")
parser.add_argument('--xml_name', dest='xml_name', action='store', help="Name of XML file to generate")
args = parser.parse_args()
jsonfile = str(args.f)
xml_name = str(args.xml_name)
if not jsonfile:
	jsonfile = 'results.json'
if not xml_name:
	xml_name = "PipelineResultsAsJunitReport.xml"

severityStrings = {}
severityStrings["0"] = "Informational"
severityStrings["1"] = "Very Low"
severityStrings["2"] = "Low"
severityStrings["3"] = "Medium"
severityStrings["4"] = "High"
severityStrings["5"] = "Very High"

'''
########################
# DATA SCHEMA
########################
scan_id
scan_status
message
findings
	title
	issue_id
	gob
	severity
	issue_type_id
	issue_type
	cwe_id
	display_text
	files
		source_file
			file
			line
			function_name
			qualified_function_name
			function_prototype
			scope
	flaw_match
		procedure_hash
		prototype_hash
		flaw_hash
		flaw_hash_count
		flaw_hash_ordinal
		cause_hash
		cause_hash_count
		cause_hash_ordinal
########################
'''

#
# IMPORT JSON AND CAPTURE DATA
#
def getJSONdata():
	#
	# Importing JSON data
	#
	try:
		with open(jsonfile) as json_file:
			pipelinedata = json.load(json_file)
			#data2 = json.dumps(pipelinedata, indent=4)
			#print(data2)			
			if pipelinedata['scan_status'] == "SUCCESS":
				vulncount=0
				for v in pipelinedata['findings']:
					title=v['title']
					issueid=str(v['issue_id'])
					severity=str(v['severity'])
					issuetype=v['issue_type']
					cweid=v['cwe_id']
					displaytext=v['display_text']
					src=v['files']['source_file']['file']
					if "/" in src:
						src_file = src.split('/')
						src_file_len = len(src_file)
						file=''.join(src_file[src_file_len-1:])
					elif "\\" in src:
						src_file = src.split('\\')
						src_file_len = len(src_file)
						file=''.join(src_file[src_file_len-1:])
					else:
						src_file = src
						file = src_file
					path=src.replace(file, '')
					line=str(v['files']['source_file']['line'])
					qualifiedfunctionname=v['files']['source_file']['qualified_function_name']
					functionprototype=v['files']['source_file']['function_prototype']
					scope=v['files']['source_file']['scope']
					flaws[vulncount]={'title' : title, 'issueid' : issueid, 'severity' : severity, 'issuetype' : issuetype, 'cweid' : cweid, 'displaytext' : displaytext, 'file' : file, 'path' : path, 'line' : line, 'qualifiedfunctionname' : qualifiedfunctionname, 'functionprototype' : functionprototype, 'scope' : scope}
					vulncount += 1
				moduleCount=0
				for module in pipelinedata['modules']:
					modules[moduleCount]= {
							'architecture':  "unknown",
							'compiler': "unknown",
							'loc': "9999",
							'name': module,
						}
					moduleCount+=1

				for flaw in flaws:
					currentToCheck = testCaseTree["children"]
					flawObj = flaws[flaw]
					splitPath = flawObj["scope"].split(".")
					for pathPart in splitPath:
						if not "children" in currentToCheck:
							currentToCheck["children"] = {}
						children = currentToCheck["children"]						
						if not pathPart in children:
							element = {"findings": [], "children": {}}
							children[pathPart] = element
						else:	
							element = children[pathPart]
						currentToCheck = element
					if element:
						findings = element["findings"]
						if not findings:
							findings = []
							element["findings"] = findings
						findings.append(flawObj)
			else:
				sys.exit("Pipeline scan status not successful")
	except Exception:
		traceback.print_exc()
		sys.exit("Error within capturing JSON data (see getJSONdata)")

def generateXmlInternalNodes(elements, testSuitesNode):
	for elementName in elements:
		elementNode = elements[elementName]
		if elementNode and elementName == "findings":
			testCaseElement = ET.SubElement(testSuitesNode, 'testsuite')
			scope = elementNode[0]["scope"]
			testCaseElement.set("name", scope)
			for finding in elementNode:
				testCaseNode = ET.SubElement(testCaseElement, "testcase")				
				testCaseNode.set("name", f'{finding["issueid"]}: {severityStrings[finding["severity"]]} Severity Finding - CWE {finding["cweid"]}')
				testCaseNode.set("classname", scope)
				testCaseNode.set("time", "1.000000")

				failureNode = ET.SubElement(testCaseNode, "failure")
				failureNode.set("message", f'{finding["issuetype"]} found at {scope} on line {finding["line"]}')
				failureNode.set("type", "ScanFinding")
				failureNode.text = finding["displaytext"]

		elif elementNode:
			generateXmlInternalNodes(elementNode, testSuitesNode)

			

def generateXML():
	try:
		#root tag testsuites
		testSuitesNode = ET.Element('testsuites')
		testSuitesNode.set('time', '1.000000')
		generateXmlInternalNodes(testCaseTree, testSuitesNode)

		# convert to XML
		report_xml = ET.tostring(testSuitesNode)

		# write XML
		with open(xml_name, "wb") as f:
			f.write(report_xml)
		print(f'Finished generating JUNIT XML at {xml_name}')
	except Exception:
		traceback.print_exc()
		sys.exit("Error writing xml report (see genXML)")

def main():
	#
	# Load JSON data
	#
	getJSONdata()

	#
	# Generate XML
	#
	generateXML()
main()
# pipeline2junitxml
<b>USAGE:  python pipeline2junitxml.py -f <results.json> --xml_name <junit_results.xml></b>
		
-f is the json file to be converted
-xml_name is the name of the xml file to create


<b>STEPS</b>
	
	- Place pipeline2junitxml.py in your pipeline output folder where your results.json file resides.
	
	- Run python pipeline2junitxml.py

	- A new file will be created called <junit_results.xml>

- This xml file can be imported into any jUnit test reader.
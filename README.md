# python-Malicious-Link-Analyzer
 A Python command line tool that leverages the VirusTotal API and Google Safe Browsing API to analyze links for potential malicious content.

## Description of the code
When you run this script, an API call is made to Virus Total and Google Safe Browsing to analyze a link. In response, Virus Total returns the number of engines that have indicated our link as malicious, while Google Safe Browsing returns the possible type of threat.

## Prerequisites

A key part of this project is the use of both **Virus Total API** and **Google Safe Browsing API**:
* Get your Virus Total API key from [this link](https://docs.virustotal.com/reference/overview)
* Get your Google Safe Browsing API key from [this link](https://developers.google.com/safe-browsing)

After you have obtained you API keys, please create a file called ```.env``` inside the root folder of the project and insert the following:
```
VIRUS_TOTAL_API_KEY="your_virus_total_api_key"
GOOGLE_SAFE_BROWSING_API_KEY="your_google_safe_browsing_api_key"
```

Alternatively the API keys can be passed directly as command line arguments with the flags:
```bash
-v my_virus_total_API_key
-g my_google_safe_browsing_API_key
```

## Installation
```bash
git clone https://github.com/federicomigliosi/python-Malicious-Link-Analyzer.git
cd python-Malicious-Link-Analyzer
pip install -r requirements.txt
```
## Usage
In order to run the script, execute the following commands based on what you want to do:

<table>
<tr>
<th>Goal</th><th>Command</th>
</tr>
<tr>
<td> Display help message </td>
<td>

```bash
python3 main.py -h
```

</td>
</tr>
<tr>
<td> Analyze a single link </td>
<td>

```bash
python3 main.py --link "https:://my.link.com"
```

</td>
</tr>
<tr>
<td> Analyze a multiple links stored in a text file </td>
<td>

```bash
python3 main.py --file "/path/to/file"
```

</td>
</tr>
</table>



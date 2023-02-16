#!/usr/bin/python3
# -*- coding: utf-8 -*-
import json
import os
import requests
import csv
import datetime
from zipfile import ZipFile
import glob

dir_path = './'

today = datetime.date.today()
current_year = year = today.year

def deep_get(d, keys, default='Empty'):
    """
    Example:
        d = {'meta': {'status': 'OK', 'status_code': 200}}
        deep_get(d, ['meta', 'status_code'])          # => 200
        deep_get(d, ['garbage', 'status_code'])       # => None
        deep_get(d, ['meta', 'garbage'], default='-') # => '-'
    """
    assert type(keys) is list
    if d is None:
        return default
    if not keys:
        return d
    return deep_get(d.get(keys[0]), keys[1:], default)

def get_and_extract_zip(file, year):
    try:
        url = 'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-%s.json.zip' % year
        r = requests.get(url, allow_redirects=True)
        open(file, 'wb').write(r.content)
        with ZipFile(file, 'r') as zipObj:
            zipObj.extractall(path=dir_path)
    except Exception as e:
        print(e)

for year in range(2017, int(current_year) + 1):
    zip_file  = dir_path + str(year) + ".zip"
    get_and_extract_zip(zip_file, year)


file = open(dir_path + 'vulners.csv', 'w', newline ='')
with file:
    # identifying header
    header = ['cve_id','v2_exploitabilityScore', 'v2_impactScore','v2_obtainAllPrivilege','v2_obtainOtherPrivilege',
    'v2_obtainUserPrivilege','v2_severity','v2_userInteractionRequired','v2_cvss2_accessComplexity','v2_cvss2_accessVector',
    'v2_cvss2_authentication','v2_cvss2_availabilityImpact','v2_cvss2_baseScore','v2_cvss2_confidentialityImpact',
    'v2_cvss2_integrityImpact','v2_cvss2_vectorString','v2_cvss2_version','v3_exploitabilityScore','v3_impactScore',
    'v3_cvss3_attackComplexity','v3_cvss3_attackVector','v3_cvss3_availabilityImpact','v3_cvss3_baseScore','v3_cvss3_baseSeverity',
    'v3_cvss3_confidentialityImpact','v3_cvss3_integrityImpact','v3_cvss3_privilegesRequired','v3_cvss3_scope','v3_cvss3_userInteraction',
    'v3_cvss3_vectorString','v3_cvss3_version']
    writer = csv.DictWriter(file, fieldnames = header)
    writer.writeheader()
file.close()

file = open(dir_path + 'vulners.csv', 'a', newline ='')
for year in range(2017, int(current_year) + 1):
    with open(dir_path + 'nvdcve-1.1-%s.json' % year) as json_file:
        data = json.load(json_file)
        arr = json.dumps(data, sort_keys=True)
        ddd = json.loads(arr)
        for i in ddd['CVE_Items']:
            final_dict = {}
            final_dict['cve_id'] = deep_get(i, ['cve', 'CVE_data_meta', 'ID'])
            final_dict['v2_exploitabilityScore'] = deep_get(i, ['impact', 'baseMetricV2', 'exploitabilityScore'])
            final_dict['v2_impactScore'] = deep_get(i, ['impact', 'baseMetricV2', 'impactScore'])
            final_dict['v2_obtainAllPrivilege'] = deep_get(i, ['impact', 'baseMetricV2', 'obtainAllPrivilege'])
            final_dict['v2_obtainOtherPrivilege'] = deep_get(i, ['impact', 'baseMetricV2', 'obtainOtherPrivilege'])
            final_dict['v2_obtainUserPrivilege'] = deep_get(i, ['impact', 'baseMetricV2', 'obtainUserPrivilege'])
            final_dict['v2_severity'] = deep_get(i, ['impact', 'baseMetricV2', 'severity'])
            final_dict['v2_userInteractionRequired'] = deep_get(i, ['impact', 'baseMetricV2', 'userInteractionRequired'])
            final_dict['v2_cvss2_accessComplexity'] = deep_get(i, ['impact', 'baseMetricV2', 'cvssV2', 'accessComplexity'])
            final_dict['v2_cvss2_accessVector'] = deep_get(i, ['impact', 'baseMetricV2', 'cvssV2', 'accessVector'])
            final_dict['v2_cvss2_authentication'] = deep_get(i, ['impact','baseMetricV2','cvssV2','authentication'])
            final_dict['v2_cvss2_availabilityImpact'] = deep_get(i, ['impact','baseMetricV2','cvssV2','availabilityImpact'])
            final_dict['v2_cvss2_baseScore'] = deep_get(i, ['impact','baseMetricV2','cvssV2','baseScore'])
            final_dict['v2_cvss2_confidentialityImpact'] = deep_get(i, ['impact','baseMetricV2','cvssV2','confidentialityImpact'])
            final_dict['v2_cvss2_integrityImpact'] = deep_get(i, ['impact', 'baseMetricV2', 'cvssV2','integrityImpact'])
            final_dict['v2_cvss2_vectorString'] = deep_get(i, ['impact', 'baseMetricV2','cvssV2', 'vectorString'])
            final_dict['v2_cvss2_version'] = deep_get(i, ['impact', 'baseMetricV2', 'cvssV2', 'version'])
            final_dict['v3_exploitabilityScore'] = deep_get(i, ['impact', 'baseMetricV3', 'exploitabilityScore'])
            final_dict['v3_impactScore'] = deep_get(i, ['impact', 'baseMetricV3', 'impactScore'])
            final_dict['v3_cvss3_attackComplexity'] = deep_get(i, ['impact', 'baseMetricV3', 'cvssV3', 'attackComplexity'])
            final_dict['v3_cvss3_attackVector'] = deep_get(i, ['impact', 'baseMetricV3', 'cvssV3', 'attackVector'])
            final_dict['v3_cvss3_availabilityImpact'] = deep_get(i, ['impact', 'baseMetricV3', 'cvssV3', 'availabilityImpact'])
            final_dict['v3_cvss3_baseScore'] = deep_get(i, ['impact', 'baseMetricV3', 'cvssV3', 'baseScore'])
            final_dict['v3_cvss3_baseSeverity'] = deep_get(i, ['impact', 'baseMetricV3', 'cvssV3', 'baseSeverity'])
            final_dict['v3_cvss3_confidentialityImpact'] = deep_get(i, ['impact', 'baseMetricV3', 'cvssV3', 'confidentialityImpact'])
            final_dict['v3_cvss3_integrityImpact'] = deep_get(i, ['impact', 'baseMetricV3', 'cvssV3', 'integrityImpact'])
            final_dict['v3_cvss3_privilegesRequired'] = deep_get(i, ['impact', 'baseMetricV3', 'cvssV3', 'privilegesRequired'])
            final_dict['v3_cvss3_scope'] = deep_get(i, ['impact', 'baseMetricV3', 'cvssV3', 'scope'])
            final_dict['v3_cvss3_userInteraction'] = deep_get(i, ['impact', 'baseMetricV3', 'cvssV3', 'userInteraction'])
            final_dict['v3_cvss3_vectorString'] = deep_get(i, ['impact', 'baseMetricV3', 'cvssV3', 'vectorString'])
            final_dict['v3_cvss3_version'] = deep_get(i, ['impact', 'baseMetricV3', 'cvssV3', 'version'])
            w = csv.DictWriter(file, header)
            w.writerow(final_dict)
            print(final_dict)
            final_dict.clean()
file.close()



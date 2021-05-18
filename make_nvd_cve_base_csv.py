#!/usr/bin/python3
# -*- coding: utf-8 -*-
import json
import os
import requests
import csv
from zipfile import ZipFile
import time
import sys
import glob
from shutil import copyfile
from datetime import datetime

nvd_years = ['2017', '2018', '2019', '2020', '2021']
dir_path = '/opt/scripts/vulners/'

my_date = datetime.now()
try:
    copyfile(dir_path + 'vulners.csv', dir_path + 'csv_backups/%s.csv' % my_date.strftime("%d-%m-%Y"))
except Exception as e:
    print(str(e) + 'Файлика нет' )

os.remove(dir_path + 'vulners.csv')
jsonlist=glob.glob(dir_path + '*.json')
ziplist = glob.glob(dir_path + '*.zip')

for file in jsonlist:
  os.remove(file)
for file in ziplist:
  os.remove(file)

file = open(dir_path + 'vulners.csv', 'w', newline ='')
with file:
    # identifying header
    header = ['cve_id', 'V2_cvssv2_vector_string', 'V3_cvssv3_vector_stringV3', 'V2_severity', 'V2_obtainUserPrivilege',
    'V2_userInteractionRequired', 'V2_obtainOtherPrivilege', 'V2_exploitabilityScore', 'V2_cvssv2_accessComplexity',
    'V2_cvssv2_integrityImpact', 'V2_cvssv2_confidentialityImpact', 'V2_cvssv2_baseScore', 'V2_cvssv2_availabilityImpact',
    'V2_cvssv2_accessVector', 'V2_cvssv2_authentication', 'V3_exploitabilityScore', 'V3_impactScore', 'V3_cvssv3_userInteraction',
    'V3_cvssv3_integrityImpact', 'V3_cvssv3_availabilityImpact', 'V3_cvssv3_attackVector', 'V3_cvssv3_baseSeverity',
    'V3_cvssv3_baseScore', 'V3_cvssv3_scope', 'V3_cvssv3_attackComplexity', 'V3_cvssv3_privilegesRequired', 'V3_cvssv3_confidentialityImpact']
    writer = csv.DictWriter(file, fieldnames = header)
    writer.writeheader()
file.close()
def deep_get(d, keys, default='Netu'):
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

for year in nvd_years:
    zip_file  = dir_path + year + ".zip"
    get_and_extract_zip(zip_file, year)

file = open(dir_path + 'vulners.csv', 'a', newline ='')
for year in nvd_years:
    with open(dir_path + 'nvdcve-1.1-%s.json' % year) as json_file:
        data = json.load(json_file)
        arr = json.dumps(data, sort_keys=True)
        ddd = json.loads(arr)
        for i in ddd['CVE_Items']:
            cve_id = deep_get(i, ['cve', 'CVE_data_meta', 'ID'])
            V2_cvssv2_vector_string = deep_get(i, ['impact', 'baseMetricV2', 'cvssV2', 'vectorString'])
            V3_cvssv3_vector_stringV3 = deep_get(i, ['impact', 'baseMetricV3', 'cvssV3', 'vectorString'])
            V2_severity = deep_get(i, ['impact', 'baseMetricV2', 'severity'])
            V2_obtainUserPrivilege = deep_get(i, ['impact', 'baseMetricV2', 'obtainUserPrivilege'])
            V2_userInteractionRequired = deep_get(i, ['impact', 'baseMetricV2', 'userInteractionRequired'])
            V2_obtainOtherPrivilege = deep_get(i, ['impact', 'baseMetricV2', 'obtainOtherPrivilege'])
            V2_exploitabilityScore = deep_get(i, ['impact', 'baseMetricV2', 'exploitabilityScore'])
            V2_cvssv2_accessComplexity = deep_get(i, ['impact', 'baseMetricV2', 'cvssV2', 'accessComplexity'])
            V2_cvssv2_integrityImpact = deep_get(i, ['impact', 'baseMetricV2', 'cvssV2', 'integrityImpact'])
            V2_cvssv2_confidentialityImpact = deep_get(i, ['impact', 'baseMetricV2', 'cvssV2', 'confidentialityImpact'])
            V2_cvssv2_baseScore = deep_get(i, ['impact', 'baseMetricV2', 'cvssV2', 'baseScore'])
            V2_cvssv2_availabilityImpact = deep_get(i, ['impact', 'baseMetricV2', 'cvssV2', 'availabilityImpact'])
            V2_cvssv2_accessVector = deep_get(i, ['impact', 'baseMetricV2', 'cvssV2', 'accessVector'])
            V2_cvssv2_authentication = deep_get(i, ['impact', 'baseMetricV2', 'cvssV2', 'authentication'])
            V3_exploitabilityScore = deep_get(i, ['impact', 'baseMetricV3', 'exploitabilityScore'])
            V3_impactScore = deep_get(i, ['impact', 'baseMetricV3', 'impactScore'])
            V3_cvssv3_userInteraction = deep_get(i, ['impact', 'baseMetricV3', 'cvssV3', 'userInteraction'])
            V3_cvssv3_integrityImpact = deep_get(i, ['impact', 'baseMetricV3', 'cvssV3', 'integrityImpact'])
            V3_cvssv3_availabilityImpact = deep_get(i, ['impact', 'baseMetricV3', 'cvssV3', 'availabilityImpact'])
            V3_cvssv3_attackVector = deep_get(i, ['impact', 'baseMetricV3', 'cvssV3', 'attackVector'])
            V3_cvssv3_baseSeverity = deep_get(i, ['impact', 'baseMetricV3', 'cvssV3', 'baseSeverity'])
            V3_cvssv3_baseScore = deep_get(i, ['impact', 'baseMetricV3', 'cvssV3', 'baseScore'])
            V3_cvssv3_scope = deep_get(i, ['impact', 'baseMetricV3', 'cvssV3', 'scope'])
            V3_cvssv3_attackComplexity = deep_get(i, ['impact', 'baseMetricV3', 'cvssV3', 'attackComplexity'])
            V3_cvssv3_privilegesRequired = deep_get(i, ['impact', 'baseMetricV3', 'cvssV3', 'privilegesRequired'])
            V3_cvssv3_confidentialityImpact = deep_get(i, ['impact', 'baseMetricV3', 'cvssV3', 'confidentialityImpact'])
            file.write('"' + str(cve_id) + '"' + ','  + '"' + str(V2_cvssv2_vector_string)\
                 + '"' + ',' + '"' + str(V3_cvssv3_vector_stringV3) + '"' + ',' + '"' + str(V2_severity)\
                      + '"' + ',' + '"' + str(V2_obtainUserPrivilege) + '"' + ',' + '"' + str(V2_userInteractionRequired)\
                           + '"' + ',' + '"' + str(V2_obtainOtherPrivilege) + '"' + ',' + '"' + str(V2_exploitabilityScore)\
                                + '"' + ',' + '"' + str(V2_cvssv2_accessComplexity) + '"' + ',' + '"' + str(V2_cvssv2_integrityImpact)\
                                     + '"' + ',' + '"' + str(V2_cvssv2_confidentialityImpact) + '"' + ',' + '"' + str(V2_cvssv2_baseScore)\
                                          + '"' + ',' + '"' + str(V2_cvssv2_availabilityImpact) + '"' + ',' + '"' + str(V2_cvssv2_accessVector)\
                                               + '"' + ',' + '"' + str(V2_cvssv2_authentication) + '"' + ',' + '"' + str(V3_exploitabilityScore)\
                                                    + '"' + ',' + '"' + str(V3_impactScore) + '"' + ',' + '"' + str(V3_cvssv3_userInteraction)\
                                                        + '"' + ',' + '"' + str(V3_cvssv3_integrityImpact) + '"' + ',' + '"' + str(V3_cvssv3_availabilityImpact)\
                                                            + '"' + ',' + '"' + str(V3_cvssv3_attackVector) + '"' + ',' + '"' + str(V3_cvssv3_baseSeverity)\
                                                                + '"' + ',' + '"' + str(V3_cvssv3_baseScore) + '"' + ',' + '"' + str(V3_cvssv3_scope)\
                                                                    + '"' + ',' + '"' + str(V3_cvssv3_attackComplexity) + '"' + ',' + '"' + str(V3_cvssv3_privilegesRequired)\
                                                                        + '"' + ',' + '"' + str(V3_cvssv3_confidentialityImpact) + '"' + '\n')
            #print(V3_cvssv3_baseScore, V3_cvssv3_baseSeverity)
            #file.write(str(V3_cvssv3_baseScore) + ',' + str(V3_cvssv3_baseSeverity) + '\n')
file.close()

#!/usr/bin/env python
# coding: utf-8

# In[1]:


import numpy as np
import os
import pickle
import logging
import yaml
import json, re
import datetime
import pandas as pd
import requests
import time
import csv
#from bs4 import BeautifulSoup
import urllib3
urllib3.disable_warnings()



from logging.handlers import RotatingFileHandler
os.environ["WORKDIR"] = '' ####TODO COMMENT OUT
verbose = True
ver = False
global scores

DATA_STREAM = 'MALIPVALIDATION'
try:
    base_path = os.path.join(os.environ["WORKDIR"],"ml_plugins")
    with open(base_path + "/" + DATA_STREAM + "/dnifconfig_MALIPVALIDATION.yml", 'rb') as ymlfile:
    #with open(DATA_STREAM + "\\dnifconfig_MALIPVALIDATION.yml", 'rb') as ymlfile:  
        cfg = yaml.load(ymlfile, yaml.Loader)
except Exception as e:
    print (e)


LOGLEVEL = cfg['ml_plugin'].get('LOGLEVEL',0)
LOGPATH = "{}/{}".format(base_path, cfg['ml_plugin'].get('LOGPATH',0))
#LOGPATH =  cfg['ml_plugin'].get('LOGPATH',0)
output_filename  = cfg['ml_plugin'].get('OUTPUT_FILE_NAME',"")
bad_output_filename  = cfg['ml_plugin'].get('BAD_OUTPUT_FILE_NAME',"")
current_time = cfg['ml_plugin'].get('CURRENT_TIME_NAME',0)
ip = cfg['ml_plugin'].get('IP_NAME',0)
vts = cfg['ml_plugin'].get('VT_SCORE_NAME',0)
dss = cfg['ml_plugin'].get('DSHIELD_NAME',0)
aips = cfg['ml_plugin'].get('ABUSE_IPDB_NAME',0)
ibm = cfg['ml_plugin'].get('IBM_NAME',0)
sa = cfg['ml_plugin'].get('SA_NAME',0)
ipq = cfg['ml_plugin'].get('IPQ_NAME',0)
ispname = cfg['ml_plugin'].get('ISP_NAME',0)
cntry = cfg['ml_plugin'].get('COUNTRY_ID',0)
ts = cfg['ml_plugin'].get('TALOS_NAME',0)
repu = cfg['ml_plugin'].get('REPUTATION',0)


logger = logging.getLogger(DATA_STREAM)
LEVELS = {0: logging.DEBUG,
          1: logging.INFO,
          4: logging.WARNING,
          5: logging.ERROR,
          6: logging.CRITICAL,
          }
level = LEVELS.get(LOGLEVEL, logging.INFO)

logger.setLevel(level)
formatter = logging.Formatter('%(asctime)s:%(levelname)s:%(name)s:%(message)s')
logHandler = RotatingFileHandler(LOGPATH , maxBytes=11534336, backupCount=10)
logHandler.setFormatter(formatter)
logger.addHandler(logHandler)

data_path = base_path +  "/" + DATA_STREAM + "/data/"
#data_path = DATA_STREAM + "\\data\\"
logger.debug (data_path)
output_path = data_path + output_filename
bad_output_path = data_path + bad_output_filename
logger.debug (output_path)

csv_col_headers_1 = [current_time,ip,ispname,cntry,vts,aips,ibm,sa,ipq,ts,repu]
csv_col_headers_2 = ["$Bad_IP","$China_IP"]


# In[2]:


def virustotal(i):
# =============================================================================
#         headers1 = {
#         'X-Tool': 'vt-ui-main',
#         'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.83 Safari/537.36',
#         'content-type': 'application/json',
#         'x-app-version': 'v1x40x0',
#         'accept': 'application/json',
#         'Referer': 'https://www.virustotal.com/',
#         'Accept-Ianguage': 'en-US,en;q=0.9,es;q=0.8',
#         'X-VT-Anti-Abuse-Header': 'MTE1NTMwMTA1MTItWkc5dWRDQmlaU0JsZG1scy0xNjMwMjMwODI4LjM2',
#         }
#         res = requests.get('https://www.virustotal.com/ui/ip_addresses/%s'%i, headers=headers1,verify=ver)
#         #wb = bs4.BeautifulSoup(r.text , "html.parser")
#         try:
#             js = json.loads(res.content)
#             jso = js["data"]["attributes"]
#             vtscore=(jso['last_analysis_stats'][ 'malicious'])
#             isp=(jso['as_owner'])
#             country_code=(jso[ 'country'])
#             return vtscore,isp,country_code
#         except KeyError:
# =============================================================================
            try:
                logger.debug("inside Virus Total")
                api_key = "16afa09cc044237b4ca7dbf634df08b8a4f72aac4495fdbce38aba455368de2b"
                req = requests.get("https://www.virustotal.com/api/v3/ip_addresses/%s"%i, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36',
                'x-apikey': '%s' % api_key},verify=False).json()
                isp = req["data"]["attributes"]["as_owner"]
                score = req["data"]["attributes"]["last_analysis_stats"]["malicious"]
                country = req["data"]["attributes"]["country"]
                
                #print(isp)
                #print(score)
                #print(country)
                isp =isp
                vtscore = score
                country_code=country
                logger.debug("Virus Total Completed")
                return vtscore,isp,country_code
            
                
            except:
                vtscore=0
                isp="Null"
                country_code="Null"
                print("Exception encountered in Virus Total")
                return vtscore,isp,country_code  



def abuseipdb(i):
    logger.debug("inside Abuse IP DB")
    try:
       url='https://api.abuseipdb.com/api/v2/check'
       headers = {'Accept':'application/json','Key':'d2d773fc059e9061a6ce85d528bfa93811dc45218e34e443a1562cf45fce00414d0e260454bcb368'}
       parameters = {'ipAddress': i,'maxAgeInDays': '90'}
       req = requests.get( url=url,headers=headers,params=parameters,verify=False)
       json_Data = json.loads(req.content)
       json_main = json_Data["data"]
       aip=json_main['abuseConfidenceScore']
       logger.debug("Abuse IP DB Completed")
    except:
        aip = 0

    return aip  



def ibm_xchange(i):
    logger.debug("inside IBM XChange")
    try:
        url1 ='https://exchange.xforce.ibmcloud.com/api/ipr/%s'%i
        headers = {'Accept': 'application/json','Authorization': 'Basic OWEwYjE0YzAtNzA5OS00MTc4LWJlZDEtMzUyMWRlMDQ4NGIyOjczNGRkZGM2LWExYzQtNDgzZC1hNDM1LTI1MjM3MjA4NzY0MQ==',}
    
        req = requests.get(headers=headers,url=url1,verify=False)
        Data = json.loads(req.content)
        js_main = Data["score"]
        IBM =(js_main)
        logger.debug("IBM XForce Completed")
    except:
        IBM = 0
   
    return IBM 


def scam(i):
    logger.debug("inside Scam")
    try:
        api_key = "https://api12.scamalytics.com/tcs/?key=8e3bc6b19ace96b459b4be08b373b827&ip=%s"%i
        req = requests.get(api_key,verify=False).json()
        scamscore=int(req["score"])
        logger.debug("Scam Completed")
    except:
        scamscore = 0   

    return scamscore



def IPQuality(i):
    logger.debug("inside IPQuality")
    try:
        req = requests.get('https://ipqualityscore.com/api/json/ip/Lvx3Iw0eh5S6lTGhPJQekqkpmebot2TB/%s'%i,verify=ver).json()
        IPQuality=req['fraud_score']
        logger.debug("IPQuality Completed")
    except:
        IPQuality = 0

    return IPQuality


def talos(i):
    logger.debug("Inside Talos")
    try:
        r_talos_blacklist = requests.get('https://www.talosintelligence.com/sb_api/blacklist_lookup',
        headers={'Referer':'https://talosintelligence.com/reputation_center/lookup?search=%s'% i,'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36'},
        params = {'query_type':'ipaddr', 'query_entry':i},verify=False).json()
        r_details = requests.get('https://talosintelligence.com/sb_api/query_lookup',
        headers={'Referer': 'https://talosintelligence.com/reputation_center/lookup?search=%s' % i,
         'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36'},
        params={'query': '/api/v2/details/ip/','query_entry': i},verify=False).json()
        r_wscore = requests.get('https://talosintelligence.com/sb_api/remote_lookup',
        headers={'Referer': 'https://talosintelligence.com/reputation_center/lookup?search=%s' % i,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36'},
        params={'hostname': 'SDS','query_string': '/score/wbrs/json?url=%s' % i},verify=False).json()
        talos_blacklisted = {'status': False}
        if 'classifications' in r_talos_blacklist['entry']:
            talos_blacklisted['status'] = True
            talos_blacklisted['classifications'] = ", ".join(r_talos_blacklist['entry']['classifications'])
            talos_blacklisted['first_seen'] = r_talos_blacklist['entry']['first_seen'] + "UTC"
            talos_blacklisted['expiration'] = r_talos_blacklist['entry']['expiration'] + "UTC"
        data = {'address': i,'hostname': r_details['hostname'] if 'hostname' in r_details else "nodata",'volume_change': r_details['daychange'] if 'daychange' in r_details else "nodata",'lastday_volume': r_details['daily_mag'] if 'daily_mag' in r_details else "nodata",'month_volume': r_details['monthly_mag'] if 'monthly_mag' in r_details else "nodata",'email_reputation': r_details['email_score_name'] if 'email_score_name' in r_details else "nodata",'web_reputation': r_details['web_score_name'] if 'web_score_name' in r_details else "nodata",'weighted_reputation_score': r_wscore['response'],
'talos_blacklisted': "Yes" if talos_blacklisted['status'] else "No",}
        talos=data['talos_blacklisted']
        logger.debug("Talos completed")
    except:
        talos = "No"

    return talos



def ValidateMalIP(inward_array, var_array):
    window = cfg['ml_plugin'].get('MEASUREMENT_WINDOW',1500)
    MALIPNAME = cfg['ml_plugin'].get('MALICIOUS_IP_NAME',0)
    Json_File_path = data_path + MALIPNAME
    csv_col_headers_1 = [current_time,ip,ispname,cntry,vts,aips,ibm,sa,ipq,ts,repu]
    csv_col_headers_2 = ["$Bad_IP","$China_IP"]
    logger.debug("Inside validate")
    temp_CSV_Path = data_path + "temp_MalIP.csv"
    logger.debug(temp_CSV_Path)
    now  = datetime.datetime.now()
    logger.debug(now)
    now_string  = now.strftime("%m-%d-%Y_%H-%M-%S")
    start_time  = now - datetime.timedelta(hours = window)
    logger.debug(start_time)
    outward_array = []
    logger.debug("before reading mal ip df")
    print (Json_File_path)
    jsonpathexist = os.path.exists(Json_File_path)
    if jsonpathexist:
        logger.debug("* MalIP Json File exists *")
        ##df_MalIP = read_mal_ip_data()
        ###len_df_MalIP = len(df_MalIP)
        ###logger.debug(len_df_MalIP)
        if(True ): ###len_df_MalIP!=0):   
       
            ###df_MalIP.to_csv(temp_CSV_Path, index=False)
    
    
            try:
                ###Detect_from_SrcIP = pd.read_csv ('/dnif/4SJ791/ml_plugins/MALIPVALIDATION/data/temp_MalIP.csv')
                #Detect_from_SrcIP = pd.read_csv ('MALIPVALIDATION/data/temp_MalIP.csv')
                ###logger.debug("Inside try of detect from csv")
                SrcIp = [v[u'$SrcIP'] for v in inward_array]###Detect_from_SrcIP["$SrcIP"].tolist()
            except Exception as e:
                print("Exception is",e)
   
            logger.debug("Validation Process initiated") 
            count = 0
            logger.debug(SrcIp)
            present_time=time.strftime('%Y-%m-%d %H:%M:00')
        
            for i in SrcIp:
                i = i.strip()
                logger.debug(i)
                scores=0
                recursion=0
                rec_bad=None
                rec_china=None
                time.sleep(6)
            #-----------------Getting Individual Scores--------------------------
                vtscore,isp,country_code=virustotal(i)
        
                if(isp == "Null"):
                    logger.debug("Error occured! Closing !!")
                    break
                elif (int(vtscore) > 3):
                    scores +=1
    
                a_ipdb=abuseipdb(i)
                logger.debug(a_ipdb)
                if (a_ipdb > 80):
                    scores += 1
    
                ibm_x=ibm_xchange(i)
                if (ibm_x > 3):
                    scores += 1
    
                sc_am=scam(i)
                if (sc_am > 15):
                    scores += 1
    
                IP_Q = IPQuality(i)
                if IP_Q >= 75:
                    scores +=1
    
                cisco=talos(i)
                if cisco=="Yes":
                    scores +=1   
    
            #var="No Reputation"
                rep=0
            #Bad_ip_var="$Bad_IP"
            #China_ip_var="$China_IP"
    
    
            #if (country_code=="cn" or country_code=="CN"):
            #   rep = 8
            #else:
                if (scores == 0 or scores == 1):
                    rep = 1
                
                elif (scores == 2):
                    rep = 0
                    
                elif (scores >= 3):
                    rep = 9
                    
            
                if(rep == 0):
                    var="Average"
                if(rep==1):
                    var="Good"
                if(rep==9):
                    var="Bad"
                    rec_bad=i
    
    
                inward_dict = {current_time:present_time,ip:i,ispname:isp,cntry:country_code,vts:vtscore,aips:a_ipdb,ibm:ibm_x,sa:sc_am,ipq:IP_Q,ts:cisco,repu:var}
                logger.debug(inward_dict)
    
                with open(output_path,"a") as filecsv:
                    writer = csv.DictWriter(filecsv, fieldnames=csv_col_headers_1)
                    writer.writerow(inward_dict)
    
            logger.debug("IP Reputation Check completed successfully ")
            outward_array.append({"$Msg": "IP Reputation Completed Successfully"})                  
        else:
            msg = "There are no data available for reputation check"
            outward_array = [{"$MLStatus": msg}]           
    else:
        logger.debug("* Mal Ips json File does not exist *")
        outward_array.append({"$Msg": "json file not available"})
 
    return outward_array


def read_mal_ip_data():
    filename = cfg['ml_plugin'].get('MALICIOUS_IP_NAME',0)
    filename = data_path + "/" +  filename
    print(filename)
    #ddf_mal_ip = pd.read_json(r'/dnif/4SJ791/ml_plugins/MALIPVALIDATION/data/MALIPs.json')
    ddf_mal_ip = pd.read_json(r'MALIPVALIDATION/data/MALIPs.json')
    print(ddf_mal_ip)
    del ddf_mal_ip["count_unique"]
    return ddf_mal_ip




def main():

    #_fetch * from module where $Name = *Mal* group count_unique $SrcIP limit 100
    #For Collect Again
    inward_array = [{u'$SrcIP': u'14.143.187.214', 'count_unique': 10}, 
                   {u'$SrcIP': u'117.192.92.85', 'count_unique': 15},
                   {u'$SrcIP': u'175.101.144.92', 'count_unique': 12},
                   {u'$SrcIP': u'186.80.52.98', 'count_unique': 20}, 
                   {u'$SrcIP': u'43.239.112.252', 'count_unique': 28}, 
                   {u'$SrcIP': u'23.90.160.146', 'count_unique': 17}]
    
    var_array = ['count_unique', '$SrcIP']
    
    print (ValidateMalIP(inward_array, var_array))
    
if __name__ == "__main__":
     main()


# In[ ]:





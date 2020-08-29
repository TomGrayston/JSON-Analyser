import json
import pandas as pd
import csv
import ipwhois
from ipwhois.asn import IPASN
from ipwhois.net import Net

def genAnalysis():
    filename = "mirai_data.json"                                    #input name of csv file
    file = open(filename, 'r',encoding='utf-16')                    #open file
    dict = json.loads(file.read())                                  #convert file to dictionary format
    Results = dict['results']                                       #grab the named section of the original file you want
    df=pd.DataFrame.from_dict(Results)                              #using the panda lib to get the data frame of the file 

                                                                    #   | All |
    S_IP = df['Source IP'].value_counts()                           # Source IP
    HP = df['Honeypot'].value_counts()                              # Honeypot
    S_P = df['Source Port'].value_counts()                          # Source Port
    D_P = df['Destination Port'].value_counts()                     # Destination Port
    P = df['Protocol'].value_counts()                               # Protocol
    TCP_F = df['TCP Flag'].value_counts()                           # TCP Flag
    TCP_Win_Size = df['TCP Window Size'].value_counts()             # TCP Window Size

                                                                    #   | Top 15 |   
    S_IP15 = df['Source IP'].value_counts().head(15)                # Source IP Top 15
    HP15 = df['Honeypot'].value_counts().head(15)                   # Honeypot Top 15
    S_P15 = df['Source Port'].value_counts().head(15)               # Source Port Top 15
    D_P15 = df['Destination Port'].value_counts().head(15)          # Destination Port Top 15
    P15 = df['Protocol'].value_counts().head(15)                    # Protocol Top 15
    TCP_F15 = df['TCP Flag'].value_counts().head(15)                # TCP Flag Top 15
    TCP_Win_Size15 = df['TCP Window Size'].value_counts().head(15)  # TCP Window Size Top 15

    #generate CSV's of resulst from the dataset
    S_IP.to_csv(r"SourceIP.csv", header=True)
    HP.to_csv(r"Honeypot.csv", header=True)
    S_P.to_csv(r"SourcePorts.csv",header=True)
    D_P.to_csv(r"DestinationPort.csv",header=True)
    P.to_csv(r"Protocol.csv",header=True)
    TCP_F.to_csv(r"TCPFlags.csv",header=True)
    TCP_Win_Size.to_csv(r"TCPWindowSize.csv",header=True)

    #generate top 15 of each CSV
    S_IP15.to_csv(r"SourceIP_15.csv", header=True)
    HP15.to_csv(r"Honeypot_15.csv", header=True)
    S_P15.to_csv(r"SourcePorts_15.csv",header=True)
    D_P15.to_csv(r"DestinationPort_15.csv",header=True)
    P15.to_csv(r"Protocol_15.csv",header=True)
    TCP_F15.to_csv(r"TCPFlags_15.csv",header=True)
    TCP_Win_Size15.to_csv(r"TCPWindowSize_15.csv",header=True)

    #generate top 1000 IP addresses CSV's
    df=pd.read_csv(r"SourceIP.csv").head(1000)
    df.to_csv(r"SourceIP_1000.csv")

def geolocate():
    df = pd.read_csv("SourceIP.csv")                                                                    #read in data from the IP csv file
    Counter = 0
    errorCounter = 0
    data=pd.DataFrame(columns=['IP','CountryCode'])                                                     #create new dataframe with the columns IP and Country Code

    for i, row in df.iterrows():
        try:
            Counter+=1
            print(Counter)
            ip=row['Source IP']
            results = IPASN(Net(ip)).lookup()                                                           #Use the panda lib to search up the IP addresses from the file 
            data=data.append({'IP':ip,'country_code':results['asn_country_code']},ignore_index=True)    #add the result of that search to the data
        except:
            print("Big Oof")
            errorCounter+=1
        
    print("Error Amount")
    print(errorCounter)

    #generate CSV's 
    data.to_csv(r"geolocatedAll.csv")
    df=pd.read_csv(r"geolocatedAll.csv")
    CC = df['country_code'].value_counts()
    CC.to_csv(r"CC_All.csv", header = True)

geolocate()
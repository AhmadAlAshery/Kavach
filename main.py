from fastapi import FastAPI, Path
from urllib.parse import urlparse
import json 
import pandas as pd
import ast
import pickle
import whois
from urllib.parse import urlparse
import socket 
import ssl
import datetime
from verify_email import verify_email
import nest_asyncio
import tensorflow as tf
import numpy as np
import pickle
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
import datetime
from sklearn.base import BaseEstimator, TransformerMixin
import ast
from pysafebrowsing import SafeBrowsing
from func import my_tokenizer
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.preprocessing import StandardScaler, OneHotEncoder, MinMaxScaler
from sklearn.impute import KNNImputer, SimpleImputer
import test
from ast import literal_eval




def ssl_extraction(row):
    hostname = row
    port = 443

    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                certificate = ssock.getpeercert()
                if certificate:
                    return 1
                else:
                    return 0
    except Exception as e:
        return 0
    
def name_servers_len(row):
    val = row.name_servers
    if type(val)==str and val[0] == "[":
        return len(val.split(','))
    elif type(val) == list:
        return len(val)
    else:
        return np.nan
def string_to_list(row, instances:str):
    try:
        return literal_eval(row[instances])
    except Exception as e:
        return row[instances]


def verifyEmail(row, instance):
    # nest_asyncio.apply()
    if row[instance] == 0:
        return row[instance]
    elif type(row[instance]) == str:
        if row[instance] in bad_emails:
            return 0
        elif verify_email(row[instance]) == True:
            return 1
        else:
            bad_emails.append(row[instance])
            return 0
    elif type(row[instance]) == list:
        x = 0
        for i in row[instance]:
            if i in bad_emails:
                pass
            elif verify_email(i) == True:
                x += 1
        return x/ len(row[instance])

def string_with_hyphen(row, a):
    if type(row[a]) == list:
        return "-".join(row[a])
    else:
        return row[a]
    

nest_asyncio.apply()   


with open('vectorizer.pkl', 'rb') as file:
    vectorizer = pickle.load(file)
    
with open('vocabulary.pkl', 'rb') as file:
    vocabulary = pickle.load(file)

# Set the vocabulary of the vectorizer
vectorizer.vocabulary_ = vocabulary

# keras = tf.keras
# final_model = keras.models.load_model("my_model")
# clf_knn =  pickle.load(open("clf_knn.sav", 'rb'))
clf_rfc = pickle.load(open("rfc.sav", 'rb'))
clf_svc = pickle.load(open("svc.sav", 'rb'))
full_pipeline = pickle.load(open("full_pipeline.sav", 'rb'))
sgd_clf =  pickle.load(open('sgd_clf.sav', 'rb'))

df = pd.read_csv("final.csv")
columns_name = list(df.columns)
columns_name.remove("result")
val_dict = {'website': 'missing',
'registrar': 'missing',
'whois_server': 'missing',
'name': 'missing',
'org': 'missing',
'emails_verify': 0,
'ssl': 0,
'updated_date_diff': 0,
'expiration_date_diff': 0,
'name_servers_len': 0,
'status_len': 0,
'pyg': 0,
'phishing': 0}
api = "AIzaSyCefCOUlN1-7MvXKfl_X393z7nOezjTXao"
s = SafeBrowsing(api)
bad_emails = [
    'abuse@godaddy.com', 'abuse@dynadot.com', 'abuse@publicdomainregistry.com',
    'abuse-contact@publicdomainregistry.com', 'abuse@laxwebtechnologies.com', 'abuse@bigrock.com',
    'abuse@wildwestdomains.com', 'abuse@domainbox.com', 'rtr-security-threats@realtimeregister.com',
    'INFO@NSIREGISTRY.COM', 'support@namebright.com', 'abuse@web.com', 'tuzhi@gmw.cn', 'domainmaster@360.cn',
    'abuse@gabia.com', 'noc@staff.cntv.cn', 'hostmaster@amazon.com', 'songzh@china.org.cn', 'ABUSE@ENOM.COM',
    'abuse@gkg.net', 'abuse@easydns.com', 'abuse@joker.com', 'abuse@gathernames.com', 'domainabuse@tucows.com',
    'abuse@ovh.net', 'abuse@amazonaws.com', 'domaine@sfr.com'
    ]




app = FastAPI(debug=True)

@app.get("/")
def index():
    return {"Hello": "to Gaurd services"}



@app.get("/check_website/{u:path}")
def check_url(u : str):
    # try:
    df = pd.read_csv("final.csv")
    url = urlparse(u).path.replace("www.", "")
    res = df[df['website'] == url].to_json(orient="split", index=False)
    if len(json.loads(res)['data'])> 0:
        return json.loads(res)

    else:
        um = urlparse(u).netloc.replace("www.", "")
        web_dict = {}
        try:
            web_dict[um] = whois.whois(um)
        except Exception as e:
            print(e, "no data on whois")



        if type(web_dict[um]["updated_date"]) == list:
            web_dict[um]["updated_date"] = (min(web_dict[um]["updated_date"])-datetime.datetime.now()).days
        elif type(web_dict[um]["updated_date"]) == datetime.datetime:
            web_dict[um]["updated_date"] = (web_dict[um]["updated_date"]-datetime.datetime.now()).days
        elif type(web_dict[um]["updated_date"]) == pd._libs.tslibs.timestamps.Timestamp:
            web_dict[um]["updated_date"] = (web_dict[um]["updated_date"]-datetime.datetime.now()).days


        if type(web_dict[um]["expiration_date"]) == list:
            web_dict[um]["expiration_date"] = (max(web_dict[um]["expiration_date"])-datetime.datetime.now()).days
        elif type(web_dict[um]["expiration_date"]) == datetime.datetime:
            web_dict[um]["expiration_date"] = (web_dict[um]["expiration_date"]-datetime.datetime.now()).days
        elif type(web_dict[um]["expiration_date"]) == pd._libs.tslibs.timestamps.Timestamp:
            web_dict[um]["expiration_date"] = (web_dict[um]["expiration_date"]-datetime.datetime.now()).days

        df = pd.DataFrame.from_dict(web_dict, orient="index").reset_index()
        df.rename(
            columns={
            "index":"website",
            "updated_date":"updated_date_diff",
            "expiration_date":"expiration_date_diff"
            }, inplace=True
        )

        for i in columns_name:
            if i not in list(df.columns):
                df[i] = np.nan



        df["ssl"] = pd.Series(ssl_extraction(um))

        X_predict = vectorizer.transform([um])
        New_predict = sgd_clf.predict(X_predict)
        df["phishing"] = New_predict  
        df['registrar'].replace(["0"], [np.nan], inplace=True)
        df["name_servers_len"] = df.apply(name_servers_len, axis=1)
        df["emails"].replace("0", 0, inplace=True)
        values={"emails": 0}
        df.fillna(value=values, inplace=True)
        df["emails"] = df.apply(string_to_list, axis=1, args=(["emails"]))
        df['emails_verify']  = df.apply(verifyEmail, axis=1, args=(["emails"]))
        df.phishing.replace("good", 1, inplace=True)
        df.phishing.replace("bad", 0, inplace=True)
        df.drop([ "name_servers", "emails"], axis=1, inplace=True)
        try:
            df["pyg"] = s.lookup_urls([u])[u]["malicious"]
        except:
            df["pyg"] = 0
        if df.name[0] is None:
            df.name = np.nan
        df.fillna(value=val_dict, inplace=True)
        
        new_df = full_pipeline.transform(df)
        # try:
        #     p = clf_rfc.predict(new_df)
        # except Exception as e:
        #     p = 0.0005
        # df['result'] = p
        # columns_name.append("result")
        df = df[columns_name]
        df["result_rfc_bad"] = clf_rfc.predict_proba(new_df)[:,0].round(4)*100
        df["result_rfc_good"] = clf_rfc.predict_proba(new_df)[:,1].round(4)*100

        # df["result_svc_bad"] = clf_svc.predict_proba(np.array(new_df))[:,0].round(4)*100
        # df["result_svc_good"] = clf_svc.predict_proba(np.array(new_df))[:,1].round(4)*100        


        return json.loads(df.to_json(orient='split', index=False))
    # except:
    #     return "Please report to imporove our services"
            






from pymongo import MongoClient
import os
from dotenv import load_dotenv

load_dotenv()


def get_mongo_uri():
    
    mongo_uri = os.environ['MONGO_URI']
    return mongo_uri

database = None


def get_database():
    
    global database
    
    MY_MONGO_URI = get_mongo_uri()
    
    client = MongoClient(MY_MONGO_URI)
    
    DB_NAME = os.environ['DB_NAME']
    
    database = client[DB_NAME]
    
    return database


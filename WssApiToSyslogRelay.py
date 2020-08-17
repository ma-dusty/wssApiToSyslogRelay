# wssApiToSyslogRelay.py
application_version = '0.15'
application_date    = '2020-08-10'
# 
# Purpose
# =======
# This program interacts with the Symantec/Broadcom Web Security Service (WSS) [Cloud Proxy] API
# to collect log data and then stream that data out as Syslog, enabling near-real time log data
# to be easily consumed by a Security Information & Event Management (SIEM) platform.
#
# Symantec WSS Documentation
# ==========================
# The WSS API Documentation is available here - https://portal.threatpulse.com/docs/sol/PDFBriefs/PDF_SyncAPI.pdf
# This program was written based on 'Revision: MAR.06.2020' of the above PDF document.
#
# Symantec API's
# ==============
# The Symantec (Symantec products) Web Security Service offers two APIs (Download and Sync) for obtaining access log data
# from the cloud. The 'Download API' restricts a client from receiving partial hour data, thus obtaining log data from the current hour
# is not possible with this API. The 'Sync API' is an enhancement to the 'Download API'. It allows a web client to obtain recently
# hardened log data from the cloud by downloading the current hour in smaller up-to-the-minute segments. 
#
# This python program utilises 'Sync API'.
#
# System specification
# ====================
# Python - Version ** MUST ** be 64-bit due to some of the file sizes involved.
# This program was developed using Python 3.8.2 64-bit.
# Memory - The files downloaded from symantec can be large. This program has been tested with a 1.5 GB ZIP file which
# decompressed to 8.18 GB !!!!! However, file sizes this size will only happen following a collection outage or
# requests being made for historical records. Under normal condition file sizes can be expected to be in the
# sub-10 MB range due to the regular polling of the WSS. For performance the preference is that the file be
# stored and processed in memory. If insufficient memory is available then the OS will likely cache it to disk and
# performance will be adversely affected.
# Cores - This program in not multi-threaded.
#
# Timings
# =======
# With default settings this program will make a request for the next batch of logs 30 seconds after finishing
# processing the previous batch.
# If a 429 Error (TOO MANY REQUESTS) is received the header suggests how long to wait before resubmitting.
# An additional 2 second is added to this suggestion.
#
# Syslog output
# =============
# This program can syslog out both the fetched WSS logs, and also the logs pretaining to this application. It is strongly 
# suggested that you set the 'wss_precursor_string' and 'app_precursor_string' in the config file to differentiate between the two log sources.
#
# Config File
# ===========
# A default config file can be generated using the '-n' option

# python3 -m pip install requests

try:
    import logging
    import logging.handlers
    import socket
    import io
    import zipfile
    from contextlib import closing
    import requests
    import gzip
    import time
    import re
    import os
    import argparse
    import configparser
    import sys
except ImportError as e:
    print("ERROR - likely that one of the Phython Modules is missing. If it's 'requests' then try running   python3 -m pip install requests")
    print(e)
    raise SystemExit



def fetch_command_line_arguments():
    parser = argparse.ArgumentParser(description='Interfaces with Symantec WSS Cloud Proxy API to download activity logs and stream them out to a SYSLOG server.')
    parser.add_argument('-c', metavar="<config_filename>", help="Specify config file")
    parser.add_argument('-n', action='store_true', help="Create a new config file: new_config.ini")
    parser.add_argument('-s', metavar="<unixTime>", type=int, help="Start time - earlist time from which WSS logs are requested, in unix time in milliseconds. If a value is specified in the config file then the value specified her on the command line is ignored")
    parser.add_argument('-e', metavar="<unixTime>", type=int, default=0, help="End time - latest time from which WSS logs are requested, in unix time in milliseconds. End time cannot be earlier than Start Time and cannot be set in the future. To contineously collect all logs, set to 0. [DEFAULT Value = 0]")
    parser.add_argument('-v', action='store_true', help="Version")

    # Either a configuration file must be specified with '-c', a new config file requested using '-n', or version '-v'
    # If neither options have been submitted then raise an error and exit.
    if parser.parse_args().c is None and parser.parse_args().n is False and parser.parse_args().v is False:
        print("ERROR - either the '-c <filename>', '-v' or '-n' switch must be used")
        print("Try -h for help")
        raise SystemExit

    if parser.parse_args().v is True:
        print('Version: v%s' %(application_version))
        print('Date: %s' %(application_date))
        raise SystemExit

    # Check the config file exists as configParser will not throw an error, but instead return an empty datasheet.
    if parser.parse_args().c is not None:
        config_file = parser.parse_args().c
        if not os.path.exists(config_file):
            print("ERROR - Configuration file not found:",config_file)
            print("Try -h for help")
            raise SystemExit

    # Start Time, if specified, check it is in milliseconds and is not in the future
    if parser.parse_args().s is not None:
        start_time = parser.parse_args().s
        if start_time > int(time.time()*1000):
            print('ERROR - Start Time is in the future:',time.strftime("%a, %d %b %Y %H:%M:%S", time.gmtime(start_time/1000)))
            print('Check the system time is correct, it is reporting today as:', time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime(time.time())))
            print("Try -h for help")
            raise SystemExit               
        elif start_time < 100000000000:
            print('ERROR - Start Time specified is',time.strftime("%a, %d %b %Y %H:%M:%S", time.gmtime(start_time/1000)))
            print('Check the system time is correct, it is reporting today as:', time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime(time.time())))
            print('Are you sure you submitted the time in ** milliseconds **, for example todays date in milliseconds is',int(time.time()*1000))
            print("Try -h for help")
            raise SystemExit

    # End Time, if specified, check that Start Time also exists and that End time in not in milliseconds
    if parser.parse_args().e != 0:
        end_time = parser.parse_args().e
        if parser.parse_args().s is None:
            print('ERROR - End Time cannot be given without a Start Time also being specified')
            print("Try -h for help")
            raise SystemExit
        elif end_time <= start_time:
            print('ERROR - End Time cannot be the same or earlier than Start Time')
            print("Try -h for help")
            raise SystemExit
        elif end_time > int(time.time()*1000):
            print('ERROR - End Time is in the future:',time.strftime("%a, %d %b %Y %H:%M:%S", time.gmtime(end_time/1000)))
            print('Check the system time is correct, it is reporting today as:', time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime(time.time())))
            print("Try -h for help")
            raise SystemExit       
        elif end_time < 100000000000:
            print('ERROR - End Time specified is',time.strftime("%a, %d %b %Y %H:%M:%S", time.gmtime(end_time/1000)))
            print('Check the system time is correct, it is reporting today as:', time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime(time.time())))
            print('Are you sure you submitted the time in ** milliseconds **, for example todays date in milliseconds is',int(time.time()*1000))
            print("Try -h for help")
            raise SystemExit          

    return parser

#######################################################
# CLASS: config
# Load, Saves and can create a default config file
# The config values are loaded into global variables
#######################################################
class config:
    def load(self, filename):

        # Read config File
        config = configparser.ConfigParser()
        config.read(filename)

        # Check expected sections and options exist
        config_structure = {
                'WSS SERVER'        : ['url', 'username', 'password'],
                'SYSLOG'            : ['server_ip', 'server_port', 'host_identifier'],
                'WSS LOGS'          : ['send_to_syslog', 'save_to_file', 'save_file_path', 'last_successful_download', 'last_token_received'],
                'APPLICATION LOGS'  : ['send_to_syslog', 'save_to_file', 'save_file_name'],
                'PAUSE TIMINGS'     : ['no_more_data_available', 'more_data_available', 'wss_error']
        }

        # Check the config file has all the expected sections and options.
        # If not, raise an error and exit.
        print('Checking configuration file:',filename)
        err = False
        for section in config_structure:
            for option in config_structure[section]:
                if not config.has_option(section, option):
                    print('ERROR - Config file is missing: [%s] %s' %(section, option))
                    err = True
        if err == True:
            raise SystemExit
        del err

        # Load the settings into global variables
        global API_PATH, API_USERNAME, API_PASSWORD
        API_PATH                            = config['WSS SERVER']['url']
        API_USERNAME                        = config['WSS SERVER']['username']
        API_PASSWORD                        = config['WSS SERVER']['password']

        global SYSLOG_SERVER_IP, SYSLOG_SERVER_PORT, SYSLOG_HOST_IDENTIFIER
        SYSLOG_SERVER_IP                    = config['SYSLOG']['server_ip'] 
        SYSLOG_SERVER_PORT                  = config['SYSLOG']['server_port']
        SYSLOG_HOST_IDENTIFIER              = config['SYSLOG']['host_identifier']

        global WSS_LOG_TO_SYSLOG, WSS_SAVE_ZIP_FILE, WSS_ZIP_FILE_PATH, WSS_TIME_OF_LAST_LOG_DOWNLOADED, WSS_LAST_TOKEN_RECEIVED
        WSS_LOG_TO_SYSLOG                   = config['WSS LOGS']['send_to_syslog']
        WSS_SAVE_ZIP_FILE                   = config['WSS LOGS']['save_to_file']
        WSS_ZIP_FILE_PATH                   = config['WSS LOGS']['save_file_path'] 
        WSS_TIME_OF_LAST_LOG_DOWNLOADED     = config['WSS LOGS']['last_successful_download'] 
        WSS_LAST_TOKEN_RECEIVED             = config['WSS LOGS']['last_token_received'] 

        global APP_LOG_TO_SYSLOG, APP_LOG_TO_FILE, APP_LOG_FILE_PATH_AND_NAME
        APP_LOG_TO_SYSLOG                   = config['APPLICATION LOGS']['send_to_syslog']
        APP_LOG_TO_FILE                     = config['APPLICATION LOGS']['save_to_file']
        APP_LOG_FILE_PATH_AND_NAME          = config['APPLICATION LOGS']['save_file_name']

        global DELAY_NO_MORE_DATA_AVAILABLE, DELAY_MORE_DATA_AVAILABLE, DELAY_WSS_ERROR
        DELAY_NO_MORE_DATA_AVAILABLE        = config['PAUSE TIMINGS']['no_more_data_available']
        DELAY_MORE_DATA_AVAILABLE           = config['PAUSE TIMINGS']['more_data_available']
        DELAY_WSS_ERROR                     = config['PAUSE TIMINGS']['wss_error']

        # Append all the values onto a single line to be sysloged out later. (Do this now as they are all string values)
        # Blank out all but the last nine characters of the username
        # Blank out all characters of the password
        config_string = API_PATH +' ,'+ '*'*len(API_USERNAME[:-12])+API_USERNAME[-12:] +' ,'+ '*'*len(API_PASSWORD) +' ,'+ SYSLOG_SERVER_IP +' ,'+ str(SYSLOG_SERVER_PORT) +' ,'+ SYSLOG_HOST_IDENTIFIER +' ,'+ WSS_LOG_TO_SYSLOG +' ,'+ WSS_SAVE_ZIP_FILE +' ,'+ WSS_ZIP_FILE_PATH +' ,'+ WSS_TIME_OF_LAST_LOG_DOWNLOADED +' ,'+ WSS_LAST_TOKEN_RECEIVED +' ,'+ APP_LOG_TO_SYSLOG +' ,'+ APP_LOG_TO_FILE +' ,'+ APP_LOG_FILE_PATH_AND_NAME +' ,'+ str(DELAY_NO_MORE_DATA_AVAILABLE) +' ,'+ str(DELAY_MORE_DATA_AVAILABLE) +' ,'+ str(DELAY_WSS_ERROR)
        
        # Check Values
        if len(API_PATH) < 1:
            print('\tERROR - url not valid')
            raise SystemExit
        else:
            print('\tWSS API url:',API_PATH)

        if len(API_USERNAME) <1:
            print('\tERROR - username not valid')
            raise SystemExit
        else:
            print('\tWSS API username:',API_USERNAME)

        if len(API_PASSWORD) <1:
            print('\tERROR - password not valid')
            raise SystemExit
        else:
            print('\tWSS API password:',API_PASSWORD)

        if len(SYSLOG_SERVER_IP) <5:
            print('\tERROR - server_ip not valid')
            raise SystemExit
        else:
            print('\tSYSLOG server IP:',SYSLOG_SERVER_IP)

        if len(SYSLOG_SERVER_PORT) <1:
            print('\tERROR - server_port not valid')
            raise SystemExit
        else:
            if not SYSLOG_SERVER_PORT.isdecimal():
                print('\tERROR - server_port contains non-numeric characters')
                raise SystemExit
            SYSLOG_SERVER_PORT = int(SYSLOG_SERVER_PORT)
            if SYSLOG_SERVER_PORT > 65535:
                print('\tERROR - server_port is invalid. Must be a port number in the range 0-65535')
                raise SystemExit
            else:
                print('\tSYSLOG server port:',SYSLOG_SERVER_PORT)            

        print('\tSYSLOG host identifier string:',SYSLOG_HOST_IDENTIFIER)

        if len(WSS_LOG_TO_SYSLOG) <1:
            print('\tERROR - WSS LOGS\\send_to_syslog not valid. Set to:   yes   or   no')
            raise SystemExit
        elif WSS_LOG_TO_SYSLOG == '1' or WSS_LOG_TO_SYSLOG.casefold() == 'yes' or WSS_LOG_TO_SYSLOG.casefold() == 'true':
            WSS_LOG_TO_SYSLOG = True
        else:
            WSS_LOG_TO_SYSLOG = False
        print('\tSend WSS logs to SYSLOG server:',WSS_LOG_TO_SYSLOG)

        if len(WSS_SAVE_ZIP_FILE) <1:
            print('\tERROR - WSS LOGS\\send_to_syslog not valid. Set to:   yes   or   no')
            raise SystemExit
        elif WSS_SAVE_ZIP_FILE == '1' or WSS_SAVE_ZIP_FILE.casefold() == 'yes' or WSS_SAVE_ZIP_FILE.casefold() == 'true':
            WSS_SAVE_ZIP_FILE = True
        else:
            WSS_SAVE_ZIP_FILE = False
        print('\tSave WSS logs to disk:',WSS_SAVE_ZIP_FILE)

        if WSS_SAVE_ZIP_FILE == True: 
            if len(WSS_ZIP_FILE_PATH) <1:
                print('\tERROR - WSS LOGS\\save_file_path not valid')
                raise SystemExit
            else:
                print('\tFile path to save WSS logs to:',WSS_ZIP_FILE_PATH)

        if len(WSS_TIME_OF_LAST_LOG_DOWNLOADED) >0:     # This is allowed to be empty , so len=0
            if not WSS_TIME_OF_LAST_LOG_DOWNLOADED.isdecimal():
                print('\tERROR - last_successful_download contains non-numeric characters')
                raise SystemExit
            WSS_TIME_OF_LAST_LOG_DOWNLOADED = int(WSS_TIME_OF_LAST_LOG_DOWNLOADED)
            if WSS_TIME_OF_LAST_LOG_DOWNLOADED > int(time.time()*1000):
                print('\tERROR - last_successful_download is in the future:',time.strftime("%a, %d %b %Y %H:%M:%S", time.gmtime(WSS_TIME_OF_LAST_LOG_DOWNLOADED/1000)))
                raise SystemExit
        print('\tWSS last_successful_download:',WSS_TIME_OF_LAST_LOG_DOWNLOADED)

        if len(WSS_LAST_TOKEN_RECEIVED) == 0:
            WSS_LAST_TOKEN_RECEIVED = 'none'
        print('\tWSS last_token_received:',WSS_LAST_TOKEN_RECEIVED)

        if len(APP_LOG_TO_SYSLOG) <1:
            print('\tERROR - APPLICATION LOGS\\send_to_syslog not valid. Set to:   yes   or   no')
            raise SystemExit
        elif APP_LOG_TO_SYSLOG == '1' or APP_LOG_TO_SYSLOG.casefold() == 'yes' or APP_LOG_TO_SYSLOG.casefold() == 'true':
            APP_LOG_TO_SYSLOG = True
        else:
            APP_LOG_TO_SYSLOG = False
        print('\tSend application logs to SYSLOG server:',APP_LOG_TO_SYSLOG)

        if len(APP_LOG_TO_FILE) <1:
            print('\tERROR - APPLICATION LOGS\\save_to_file not valid. Set to:   yes   or   no')
            raise SystemExit
        elif APP_LOG_TO_FILE == '1' or APP_LOG_TO_FILE.casefold() == 'yes' or APP_LOG_TO_FILE.casefold() == 'true':
            APP_LOG_TO_FILE = True
        else:
            APP_LOG_TO_FILE = False
        print('\tSave application logs to disk:',APP_LOG_TO_FILE)

        if APP_LOG_TO_FILE == True:
            if len(APP_LOG_FILE_PATH_AND_NAME) <1:
                print('\tERROR - APPLICATION LOGS\\save_file_name not valid')
                raise SystemExit
            else:
                print('\tApplication logs, file path and name:',APP_LOG_FILE_PATH_AND_NAME)

        if len(DELAY_NO_MORE_DATA_AVAILABLE) <1:
            print('\tERROR - no_more_data_available not valid')
            raise SystemExit
        else:
            if not DELAY_NO_MORE_DATA_AVAILABLE.isdecimal():
                print('\tERROR - no_more_data_available contains non-numeric characters')
                raise SystemExit
            DELAY_NO_MORE_DATA_AVAILABLE = int(DELAY_NO_MORE_DATA_AVAILABLE)
            print('\tDelay between requests when no more data is available:',DELAY_NO_MORE_DATA_AVAILABLE,'seconds')  

        if len(DELAY_MORE_DATA_AVAILABLE) <1:
            print('\tERROR - more_data_available not valid')
            raise SystemExit
        else:
            if not DELAY_MORE_DATA_AVAILABLE.isdecimal():
                print('\tERROR - more_data_available contains non-numeric characters')
                raise SystemExit
            DELAY_MORE_DATA_AVAILABLE = int(DELAY_MORE_DATA_AVAILABLE)
            print('\tDelay between requests when more data is available:',DELAY_MORE_DATA_AVAILABLE,'seconds')

        if len(DELAY_WSS_ERROR) <1:
            print('\tERROR - wss_error not valid')
            raise SystemExit
        else:
            if not DELAY_WSS_ERROR.isdecimal():
                print('\tERROR - wss_error contains non-numeric characters')
                raise SystemExit
            DELAY_WSS_ERROR = int(DELAY_WSS_ERROR)
            print('\tDelay between requests when there has been a WSS error:',DELAY_WSS_ERROR,'seconds')

        return config_string

    def save(self, filename):
        # Write Config File
        config = configparser.ConfigParser()
        config['WSS SERVER']                                = {}
        config['WSS SERVER']['url']                         = API_PATH
        config['WSS SERVER']['username']                    = API_USERNAME
        config['WSS SERVER']['password']                    = API_PASSWORD

        config['SYSLOG']                                    = {}
        config['SYSLOG']['server_ip']                       = SYSLOG_SERVER_IP
        config['SYSLOG']['server_port']                     = str(SYSLOG_SERVER_PORT)
        config['SYSLOG']['#host_identifier']                = 'host_identifier needs to be unique for each instance of this script running. This app will append to it the WSS tenant_id for the proxy logs, or -APP for this applications logs.'
        config['SYSLOG']['host_identifier']                 = SYSLOG_HOST_IDENTIFIER

        config['WSS LOGS']                                  = {}
        config['WSS LOGS']['send_to_syslog']                = 'yes' if WSS_LOG_TO_SYSLOG else 'no'
        config['WSS LOGS']['save_to_file']                  = 'yes' if WSS_SAVE_ZIP_FILE else 'no'
        config['WSS LOGS']['save_file_path']                = WSS_ZIP_FILE_PATH
        config['WSS LOGS']['last_successful_download']      = str(WSS_TIME_OF_LAST_LOG_DOWNLOADED)
        config['WSS LOGS']['last_token_received']           = WSS_LAST_TOKEN_RECEIVED

        config['APPLICATION LOGS']                          = {}
        config['APPLICATION LOGS']['send_to_syslog']        = 'yes' if APP_LOG_TO_SYSLOG else 'no'
        config['APPLICATION LOGS']['save_to_file']          = 'yes' if APP_LOG_TO_FILE else 'no'
        config['APPLICATION LOGS']['save_file_name']        = APP_LOG_FILE_PATH_AND_NAME

        config['PAUSE TIMINGS']                             = {}
        config['PAUSE TIMINGS']['no_more_data_available']   = str(DELAY_NO_MORE_DATA_AVAILABLE)
        config['PAUSE TIMINGS']['more_data_available']      = str(DELAY_MORE_DATA_AVAILABLE)
        config['PAUSE TIMINGS']['wss_error']                = str(DELAY_WSS_ERROR)

        with open(filename, 'w') as configfile:
            config.write(configfile)

    def create_new(self, filename):
        global API_PATH, API_USERNAME, API_PASSWORD
        global SYSLOG_SERVER_IP, SYSLOG_SERVER_PORT, SYSLOG_HOST_IDENTIFIER
        global WSS_LOG_TO_SYSLOG, WSS_SAVE_ZIP_FILE, WSS_ZIP_FILE_PATH, WSS_TIME_OF_LAST_LOG_DOWNLOADED, WSS_LAST_TOKEN_RECEIVED
        global APP_LOG_TO_SYSLOG, APP_LOG_TO_FILE, APP_LOG_FILE_PATH_AND_NAME
        global DELAY_NO_MORE_DATA_AVAILABLE, DELAY_MORE_DATA_AVAILABLE, DELAY_WSS_ERROR

        API_PATH                            = "https://portal.threatpulse.com/reportpod/logs/sync"
        API_USERNAME                        = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
        API_PASSWORD                        = "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"

        SYSLOG_SERVER_IP                    = '127.0.0.1'
        SYSLOG_SERVER_PORT                  = 514
        SYSLOG_HOST_IDENTIFIER              = 'unique_for_each_instance_of_this_script'
 
        WSS_LOG_TO_SYSLOG                   = True      # Send the WSS logs to a SYSLOG Server
        WSS_SAVE_ZIP_FILE                   = False     # Save the WSS logs to a local disk
        WSS_ZIP_FILE_PATH                   = 'c:\\wss' # path to use when saving a local copy of the WSS files
        WSS_TIME_OF_LAST_LOG_DOWNLOADED     = '' 
        WSS_LAST_TOKEN_RECEIVED             = 'none' 

        APP_LOG_TO_SYSLOG                   = True
        APP_LOG_TO_FILE                     = False
        APP_LOG_FILE_PATH_AND_NAME          = 'application.log'

        DELAY_NO_MORE_DATA_AVAILABLE        = 30
        DELAY_MORE_DATA_AVAILABLE           = 0
        DELAY_WSS_ERROR                     = 600

        self.save(filename)
# End of Class - config

######################################
# CLASS: wss_api_class
# Manages interfacing with the WSS API
# Enables request to be made, responses received and the extraction of token key-pairs
######################################
class wss_api_class:
    def __init__(self):
        # Establish the following class variables specific to this instance but accessable anywhere within the class.
        #
        # Timestamps
        # ----------
        # All datetime stamp variables are integers containing the 'Unix epoch' (also known as Unix time, POSIX time or Unix timestamp) in ** milliseconds **.        
        #   - startDate. The start of the time range (earlist time) from which logs are requested.
        #   - endDate. The end of the time range (latest time) from which logs are requested. The endDate cannot occur in the future. If all logs upto the current time is required then endDate should be set to 0.
        # i.e. a startDate of 320835600000 and endDate of 320857200000 would request logs for 2nd March 1980 9:00AM to 2nd March 1980 3:00PM
        # i.e. a startDate of 320835600000 and endDate of 0 would request logs for 2nd March 1980 9:00AM upto the current date.
        self.startDate = 0
        self.endDate = 0
        # 
        # Token
        # -----
        # A token is returned by the API following each successful request. It enables a previous Sync session to be resumed without
        # loss or duplication of data. i.e. it is like a book mark. The amount of data requested may be to large to be returned in one
        # session/download, and therefore subsequent request need to be submitted with the Token to ensure next batch of data starts from where the previous batch ended.
        #   - token. An ACSII string, typicially of 68 characters, or the value of 'none'
        self.token = 'none'
        #
        # SyncTrailer - key-value pairs
        # -----------------------------
        # Appended to the end of each ZIP file are two, key-value pairs that need to be found. 
        #   - xSyncToken. Extracted from X-sync-token. The token is an ACSII string typicially 68 characters long. In the absence of a token this can be set to none.
        #   - xSyncStatus. Extracted from X-sync-status. X-sync-status can contain the following values:
        #           done - The request was satisfied and no more data is currently available within the specified date range.
        #           more - The archive was intentionally limited in size and another request with the new token would obtain more contiguous data immediately.
        #           abort - The WSS experienced a failure while building the archive. The archive might or might not contain usable data. (abort is abreviated to 'abor' when stored in xSyncStatus)
        self.xSyncToken=''
        self.xSyncStatus=''
        #
        # response
        # --------
        # Contains the response received from the API following an HTTP GET request.
        self.response =''

    def requestDownload(self):
        # Initiates a connection to the API and stores the responce (HTTP error codes, headers, content, etc) in the class variable self.response

        # The username and password must be submitted in the headers of each HTTP GET request.
        # These are contained within the configuration file.
        headers = {
            'x-APIUsername' : API_USERNAME,
            'x-APIPassword' : API_PASSWORD   
        }

        # All datetime stamp variables submitted to Symantec must be a whole hour. i.e. 10:00 and not 10:05.
        # Hence, int(xxx/60/60)*60*60 rounds the milliseconds time down to the nearest whole hour.
        self.startDate = int(self.startDate/1000/60/60)*1000*60*60

        # The start timestamp, end timestamp, and token must be submitted as parameters within each HTTP GET request. 
        params = {
            'startDate' : self.startDate,
            'endDate'   : self.endDate,
            'token'     : self.token
        }

        # The URL and path of the API.
        # This is contained within the configuration file.
        path = API_PATH

        # For performance monitoring, record the time at which the API call was made.
        time_requestMade=time.time()

        appLog.info('Making request to: %s Parameters: %s', path, params, extra={'date_time' : time.strftime("%b %d %H:%M:%S", time.gmtime(time.time()))})
        # Make the HTTP GET request
        try:
            self.response = requests.get(path, headers=headers, params=params, timeout=1800)       
        except requests.exceptions.RequestException as e:
            return e
        appLog.info('WSS took: %.2f seconds to respond to the request. Headers returned: %s',time.time()-time_requestMade, self.response.headers, extra={'date_time' : time.strftime("%b %d %H:%M:%S", time.gmtime(time.time()))})
#        appLog.info('Content: %s',self.response.content, extra={'date_time' : time.strftime("%b %d %H:%M:%S", time.gmtime(time.time()))})
#        appLog.info('Text: %s',self.response.text, extra={'date_time' : time.strftime("%b %d %H:%M:%S", time.gmtime(time.time()))})
#        appLog.info('Status Code: %i',self.response.status_code, extra={'date_time' : time.strftime("%b %d %H:%M:%S", time.gmtime(time.time()))})
#        appLog.info('JSON: %s',self.response.json(), extra={'date_time' : time.strftime("%b %d %H:%M:%S", time.gmtime(time.time()))})

    def getSyncTrailer(self):
        # The successful Sync API response is a compressed archive file with a small sync trailer appended to it. The sync trailer does
        # not impact the decompression of the archive file, but contains two key-value pairs: X-sync-status and X-sync-token. The
        # Sync Trailer is only sent in the final chunk encoding, and only when the response is 200.       

        # fetch the last 150 bytes of the file, or the whole file if less than 150 bytes long
        finalData=self.response.content[-min(len(self.response.content),150):]
        finalData=str(finalData)

        # Find the position of the two key-value pairs
        pos_xSyncToken=finalData.find('X-sync-token: ')
        pos_xSyncStatus=finalData.find('X-sync-status: ')

        # Extract the two key-value pairs
        self.xSyncToken=finalData[pos_xSyncToken+14:pos_xSyncStatus-4]
        self.xSyncStatus=finalData[pos_xSyncStatus+15:pos_xSyncStatus+19]

        # Write the results to the log file
        appLog.info('ZIP File downloaded - %i bytes', len(self.response.content), extra={'date_time' : time.strftime("%b %d %H:%M:%S", time.gmtime(time.time()))})        
        appLog.info('X-sync-token: %s', self.xSyncToken, extra={'date_time' : time.strftime("%b %d %H:%M:%S", time.gmtime(time.time()))})
        appLog.info('X-sync-status: %s', self.xSyncStatus, extra={'date_time' : time.strftime("%b %d %H:%M:%S", time.gmtime(time.time()))})
# End of class - wss_api_class

##################################################################################################################################################################################
# FUNCTION: processZipFile
#
# This function processes the ZIP file that results from a successful request made to the WSS API.
# If logs were returned then these are in text (.log) format and compressed using gZip (.gz). Multiple gZip files may exist and are then wrapped into a single ZIP file.
# If there were no logs to be returned then the ZIP file is not an archives and only contains the SyncTrailer.
# The ZIP (.zip) use the following naming convention: cloud_archive_YYYYMMDDHHMMSS.zip where the timestamp is when the logs were requested 
# The gZip (.gz) files use the following naming convention: cloud_XXXXX_YYYYMMDDHHMMSS.zip where XXXXX is the cloud instance ID and the timestamp pertains to the log entries     
#
# This program is designed to hold the ZIP file in memory and perform all subsequent operations in memory.
# This offers a significant speed advantage to writing the ZIP to disk, and then extracting and writing the log archives back to disk.
# 
# For archiving/debugging purposes it is possible to write the ZIP file to disk by setting WSS_LOGS_SAVE_TO_FILE to True, although
# all the subsequent operations (decompressing and extracting the gZip files and writing them out to syslog) is still performed on the copy held in memory.
##################################################################################################################################################################################
def processZipFile(response):

    global SYSLOG_HOST_IDENTIFIER

    time_on_last_gzip_file = False

    # Fetch the name of the ZIP file
    try:
        zip_filename=re.findall("filename=\"(.+)\"", response.headers['content-disposition'])[0]
    except:
        zip_filename=str(time.time())+'.zip'
        appLog.info('The header didnt contain the name of the ZIP file. Therefore saving as %s', zip_filename, extra={'date_time' : time.strftime("%b %d %H:%M:%S", time.gmtime(time.time()))})        

    # Save the ZIP file to disk?
    if WSS_SAVE_ZIP_FILE == True:
        temp_saveZipStart=time.time()
        open(WSS_ZIP_FILE_PATH + os.path.sep + zip_filename, 'wb').write(response.content)    
        appLog.info('%s - saving to %s%s%s - Bytes written %i - Time taken to write file to disk: %.2f seconds', zip_filename, WSS_ZIP_FILE_PATH, os.path.sep, zip_filename, len(response.content), time.time()-temp_saveZipStart, extra={'date_time' : time.strftime("%b %d %H:%M:%S", time.gmtime(time.time()))})
    else:
        appLog.info('%s - Not saving to disk', zip_filename, extra={'date_time' : time.strftime("%b %d %H:%M:%S", time.gmtime(time.time()))})

    # Check if the ZIP file is a valid ZIP. If it isn't then likely
    # it is just a SyncTrailer. SyncTrailers are normally 41, 105 or 204 characters long.
    if not zipfile.is_zipfile(io.BytesIO(response.content)):
        if len(response.content) == 41 or len(response.content) == 105:
            appLog.info('%s - Is not a valid ZIP file, it is just a Sync Trailer', zip_filename, extra={'date_time' : time.strftime("%b %d %H:%M:%S", time.gmtime(time.time()))})
        else:
            appLog.error('%s - Is not a valid ZIP file. REQUIRES INVESTIGATION. Only file sizes of 41, 105 or 203 are expected if its not a vlid ZIP, however this ZIP file length was: %i', zip_filename, len(response.content), extra={'date_time' : time.strftime("%b %d %H:%M:%S", time.gmtime(time.time()))})
    elif len(response.content) == 203:
        appLog.warning('%s - Is not a valid ZIP file, a file length of 203 is an indicator that Broadcom has sent a partial zip file and typicially will never return a valid zip file with this token. Therefore the token needs to be reset.', zip_filename, extra={'date_time' : time.strftime("%b %d %H:%M:%S", time.gmtime(time.time()))})
        return 'RESET_TOKEN'
    else:
        # This is a vlid ZIP file so continue processing
        
        # For debugging, you may wish to load a pre-existing ZIP from disk rather than initiate a new download.
        # If so, use this:   with zipfile.ZipFile('c:\\wss\\cloud_archive_200407220229.zip') as archive:

        # decompress the ZIP file
        time_zipStart = time.time()
        appLog.info('%s - Decompressing started', zip_filename, extra={'date_time' : time.strftime("%b %d %H:%M:%S", time.gmtime(time.time()))})
        with closing(response), zipfile.ZipFile(io.BytesIO(response.content)) as archive:
            appLog.info('%s - Decompressing finished. Time taken: %.2f seconds', zip_filename, time.time()-time_zipStart, extra={'date_time' : time.strftime("%b %d %H:%M:%S", time.gmtime(time.time()))})               
            appLog.info('%s - Contains %i file(s): %s', zip_filename, len(archive.namelist()), archive.namelist(), extra={'date_time' : time.strftime("%b %d %H:%M:%S", time.gmtime(time.time()))})
            # Loop through each gzip file
            for member in archive.namelist():
                if member[-3:] == '.gz':
                    # Send the data out by SYSLOG?
                    if WSS_LOG_TO_SYSLOG == True:                       
                        time_gzipStart = time.time()
                        appLog.info('%s - Decompressing started', member, extra={'date_time' : time.strftime("%b %d %H:%M:%S", time.gmtime(time.time()))})
                        try:
                            log_file = gzip.decompress(archive.read(member))
                        except:
                            appLog.critical('%s - ERROR Decompressing gzip file - NEEDS INVESTIGATING', member, extra={'date_time' : time.strftime("%b %d %H:%M:%S", time.gmtime(time.time()))})
                        else:
                            appLog.info('%s - Decompressing finished. Time taken: %.2f', member,time.time()-time_gzipStart, extra={'date_time' : time.strftime("%b %d %H:%M:%S", time.gmtime(time.time()))})
                            
                            
                            # Do not try and decode the whole file and then split the file, as commented out below, as it consumes too much memory.
                            # Instead read the next line until a '\r\n' then decode that, send to syslog, repeat.

                            appLog.info('%s - Split, Decode & Sending to SYSLOG started', member, extra={'date_time' : time.strftime("%b %d %H:%M:%S", time.gmtime(time.time()))})
                            time_syslogStart = time.time()
                            count_syslog_sent=0
                            print('one \'.\' for every 1,000 lines sent:')

                            pos=0
                            while pos<len(log_file):
                                pos_next_lcr = pos + log_file[pos:pos+25000].find(b'\n') # limit find to searching in the next 25,000 characters (The longest log message to date is 18,000). If you do not limit the search then it takes forever!
                                log_line = log_file[pos:pos_next_lcr]
                                log_line_decoded = log_line.decode("iso8859-15")
                                pos = pos_next_lcr+1                                        # advance pos by 1 beyonde the last \n (\n takes up 1 bytes not 2)

                                if log_line_decoded[:1] == '#':
                                    appLog.info('%s - Comment in log file: %s', member, log_line_decoded, extra={'date_time' : time.strftime("%b %d %H:%M:%S", time.gmtime(time.time()))})
                                else:
                                    # Extract the first few fields from the log message.
                                    # Fields: x-bluecoat-request-tenant-id date time x-bluecoat-appliance-name time-taken c-ip cs-userdn cs-auth-groups x-exception-id sc-filter-result cs-categories cs(Referer) sc-status s-action cs-method rs(Content-Type) cs-uri-scheme cs-host cs-uri-port cs-uri-path cs-uri-query cs-uri-extension cs(User-Agent) s-ip sc-bytes cs-bytes x-icap-reqmod-header(X-ICAP-Metadata) x-icap-respmod-header(X-ICAP-Metadata) x-data-leak-detected x-virus-id x-bluecoat-location-id x-bluecoat-location-name x-bluecoat-access-type x-bluecoat-application-name x-bluecoat-application-operation r-ip r-supplier-country x-rs-certificate-validate-status x-rs-certificate-observed-errors x-cs-ocsp-error x-rs-ocsp-error x-rs-connection-negotiated-ssl-version x-rs-connection-negotiated-cipher x-rs-connection-negotiated-cipher-size x-rs-certificate-hostname x-rs-certificate-hostname-categories x-cs-connection-negotiated-ssl-version x-cs-connection-negotiated-cipher x-cs-connection-negotiated-cipher-size x-cs-certificate-subject cs-icap-status cs-icap-error-details rs-icap-status rs-icap-error-details s-supplier-ip s-supplier-country s-supplier-failures x-cs-client-ip-country cs-threat-risk x-rs-certificate-hostname-threat-risk x-client-agent-type x-client-os x-client-agent-sw x-client-device-id x-client-device-name x-client-device-type x-client-security-posture-details x-client-security-posture-risk-score x-bluecoat-reference-id x-sc-connection-issuer-keyring x-sc-connection-issuer-keyring-alias x-cloud-rs x-bluecoat-placeholder cs(X-Requested-With) x-random-ipv6 x-bluecoat-transaction-uuid
                                    log_line_wss_fields = log_line_decoded.split(" ",4)

                                    log_message_x_bluecoat_request_tenant_id    = log_line_wss_fields[0]
                                    log_message_date                            = log_line_wss_fields[1]
                                    log_message_time                            = log_line_wss_fields[2]
                                    log_message_x_bluecoat_appliance_name       = log_line_wss_fields[3]

                                    # Extract the WSS date time stamp so it can be reformatted to the syslog standard and placed in the appropriate place in the syslog header
                                    # As this is a relay, after the <Priority> field in the syslog message, insert: mmm dd hh:mm:ss <identifier-tenant_id> <message>
                                    log_message_date_as_time_object = time.strptime(log_message_date,'%Y-%m-%d')
                                    log_message_date_in_syslog_format = time.strftime('%b %d', log_message_date_as_time_object )

                                    wssLog.info('%s %s %s-%s %s', log_message_date_in_syslog_format, log_message_time, SYSLOG_HOST_IDENTIFIER, log_message_x_bluecoat_request_tenant_id, log_line_decoded)
                                    count_syslog_sent +=1
                                    if count_syslog_sent % 1000 == 0:
                                        print('.', end ="")

                            time_syslogEnd=time.time()
                            print('')
                            
                            # Calculate Messages Per Second (MPS)
                            KMPS = ((count_syslog_sent / (time_syslogEnd-time_syslogStart)) / 1000)

                            appLog.info('%s - Sending out to SYSLOG finished. %i lines sent. Time taken: %.2f seconds. K-MPS=%.4f',member, count_syslog_sent, time_syslogEnd-time_syslogStart, KMPS, extra={'date_time' : time.strftime("%b %d %H:%M:%S", time.gmtime(time.time()))})                       
                    else:
                        appLog.info('%s - GZip files not decompressed and not sent out via SYSLOG', member)                       

                    # The gzip filename is recorded and the date time extracted from its filename to be recorded in the config file.
                    time_on_last_gzip_file = int(time.mktime(time.strptime(member[12:25], '%Y%m%d%H%M%S'))*1000)

                else:
                    appLog.error('%s - Unrecognised file', member, extra={'date_time' : time.strftime("%b %d %H:%M:%S", time.gmtime(time.time()))})
        appLog.info('%s - Finished processing. TOTAL time taken (excluding the download): %.2f seconds.', zip_filename, time.time()-time_zipStart, extra={'date_time' : time.strftime("%b %d %H:%M:%S", time.gmtime(time.time()))})
    return time_on_last_gzip_file
                    
################
# Main Program #
################ 

# Fetch the command line arguments
cli_args = fetch_command_line_arguments()
# FYI:
#   cli_args.parse_args().n - True of False - New config file required
#   cli_args.parse_args().c - config file name
#   cli_args.parse_args().s - WSS log start time in milliseconds unix time
#   cli_args.parse_args().e - WSS log end time in milliseconds unix time

# Is a new config file being requested?
if cli_args.parse_args().n:
    conf=config()
    conf.create_new('new_config.ini')
    print('Configuration file created: new_config.ini')
    del conf
    raise SystemExit

# Load the configuration
conf=config()
config_string=conf.load(cli_args.parse_args().c)

# Set up application logging
appLog = logging.getLogger("appLog")
appLog.setLevel(logging.DEBUG)

if True:
    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.DEBUG)
    stream_handler.setFormatter(logging.Formatter('%(message)s'))
    appLog.addHandler(stream_handler)

if APP_LOG_TO_FILE:
    file_handler = logging.handlers.TimedRotatingFileHandler(filename=APP_LOG_FILE_PATH_AND_NAME, when='midnight', backupCount=30)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
    appLog.addHandler(file_handler)


if APP_LOG_TO_SYSLOG:
    syslog_handler = logging.handlers.SysLogHandler(address=(SYSLOG_SERVER_IP, SYSLOG_SERVER_PORT))
    syslog_handler.setLevel(logging.DEBUG)
    # As this is a relay, after the <Priority> field in the syslog message, insert: mmm dd hh:mm:ss <identifier> <message>
    syslog_handler.setFormatter(logging.Formatter('%(date_time)s '+SYSLOG_HOST_IDENTIFIER+'-APP '+'msg="%(message)s"'))    
    appLog.addHandler(syslog_handler)

# Set up WSS logging
if WSS_LOG_TO_SYSLOG:
    wssLog = logging.getLogger("wssLog")
    wssLog.setLevel(logging.DEBUG)
    syslog_handler = logging.handlers.SysLogHandler(address=(SYSLOG_SERVER_IP, SYSLOG_SERVER_PORT))
    syslog_handler.setLevel(logging.DEBUG)
    syslog_handler.setFormatter(logging.Formatter('%(message)s'))
    wssLog.addHandler(syslog_handler)

appLog.info('Script Name - %s', __file__, extra={'date_time' : time.strftime("%b %d %H:%M:%S", time.gmtime(time.time()))})
appLog.info('Script Version: %s', application_version, extra={'date_time' : time.strftime("%b %d %H:%M:%S", time.gmtime(time.time()))})
appLog.info('Script Date: %s', application_date, extra={'date_time' : time.strftime("%b %d %H:%M:%S", time.gmtime(time.time()))})


# Check this is a 64-bit version of Python shell
import struct
bits = 8 * struct.calcsize("P")
if bits != 64:
    appLog.critical('This application requires a 64-bit verson of Python. This version of python is only %i-bit', bits, extra={'date_time' : time.strftime("%b %d %H:%M:%S", time.gmtime(time.time()))})
    raise SystemExit

# If App Syslog enabled, Syslog out the CLI args and config file
if APP_LOG_TO_SYSLOG:
    # Collapse the command line args into a single string
    listToStr = ' '.join([str(elem) for elem in sys.argv[1:]])
    appLog.info('CLI args: ' + listToStr, extra={'date_time' : time.strftime("%b %d %H:%M:%S", time.gmtime(time.time()))})
    del listToStr

    # syslog out the config file
    appLog.info('Config file: ' + config_string, extra={'date_time' : time.strftime("%b %d %H:%M:%S", time.gmtime(time.time()))})

# initiate the WSS API
wss = wss_api_class()

# Set the configuration variables
wss.endDate = cli_args.parse_args().e
wss.token = WSS_LAST_TOKEN_RECEIVED
# WSS_TIME_OF_LAST_LOG_DOWNLOADED can be specified in either the config file or at the command line.
# The config file takes priority. If it is set within the config file then WSS_TIME_OF_LAST_LOG_DOWNLOADED will be an integer.
# otherwise, need to check if a value was given at the command line.
# If WSS_TIME_OF_LAST_LOG_DOWNLOADED is not configured in both the config file and command line, then set to zero
if isinstance(WSS_TIME_OF_LAST_LOG_DOWNLOADED, int) and cli_args.parse_args().s is not None:
    wss.startDate = WSS_TIME_OF_LAST_LOG_DOWNLOADED
    appLog.info('Start time was given in both the config file (last_successful_download) and the command line. The config file takes priority. Therefore start time is set to: %s', time.strftime("%a, %d %b %Y %H:%M:%S", time.gmtime(wss.startDate/1000)), extra={'date_time' : time.strftime("%b %d %H:%M:%S", time.gmtime(time.time()))})
elif isinstance(WSS_TIME_OF_LAST_LOG_DOWNLOADED, int) and cli_args.parse_args().s is None:
    wss.startDate = WSS_TIME_OF_LAST_LOG_DOWNLOADED
    appLog.info('Start time was given in the config file (last_successful_download) and not the command line. Start time loaded from the config file: %s', time.strftime("%a, %d %b %Y %H:%M:%S", time.gmtime(wss.startDate/1000)), extra={'date_time' : time.strftime("%b %d %H:%M:%S", time.gmtime(time.time()))})
elif not isinstance(WSS_TIME_OF_LAST_LOG_DOWNLOADED, int) and cli_args.parse_args().s is not None:
    wss.startDate = cli_args.parse_args().s
    appLog.info('Start time was not given in the config file (last_successful_download) but was specified on the the command line: %s', time.strftime("%a, %d %b %Y %H:%M:%S", time.gmtime(wss.startDate/1000)), extra={'date_time' : time.strftime("%b %d %H:%M:%S", time.gmtime(time.time()))})
elif not isinstance(WSS_TIME_OF_LAST_LOG_DOWNLOADED, int) and cli_args.parse_args().s is None:
    wss.startDate = 0
    appLog.info('Start time was not given in either the config file (last_successful_download) or the command line. Therefore setting to zero: %s', time.strftime("%a, %d %b %Y %H:%M:%S", time.gmtime(wss.startDate/1000)), extra={'date_time' : time.strftime("%b %d %H:%M:%S", time.gmtime(time.time()))})

# Start an inifinate loop to contineously poll the WSS API service with download requests and process the returned data.
while True:
    err = wss.requestDownload()
    if err:
        appLog.error('***** %s', err, extra={'date_time' : time.strftime("%b %d %H:%M:%S", time.gmtime(time.time()))})
        coolOffPeriod=DELAY_WSS_ERROR
    else:
        if wss.response.status_code == 200:
            # The download was successful. Need to process the downloaded ZIP file to:
            #   (1) Extract the SyncTrailer - a small amount of data appended to the end of the ZIP file which contains a X-sync-status and X-sync-token key-value pairs.
            #   (2) Extract the logs and stream them as syslog.

            # Extract the SyncTrailer
            # this will populate the xSyncStatus and xSyncToken class variables. These are used to determine if more logs are available for download and to update the token value. 
            wss.getSyncTrailer()    
    
            # Extract the logs and stream them as syslog.
            time_on_last_gzip_file = processZipFile(wss.response)
            if time_on_last_gzip_file == False:
                WSS_TIME_OF_LAST_LOG_DOWNLOADED = WSS_TIME_OF_LAST_LOG_DOWNLOADED
            elif time_on_last_gzip_file == 'RESET_TOKEN':
                wss.token = 'none'
                wss.startDate = WSS_TIME_OF_LAST_LOG_DOWNLOADED
                continue
            else:    
                WSS_TIME_OF_LAST_LOG_DOWNLOADED = time_on_last_gzip_file

            if wss.xSyncStatus == 'more':
                # Data was returned and more data is available. The WSS chose to limit
                # the amount of data returned in this response. The client knows that
                # another request would obtain more data immediately. The client
                # provides the new token in the next request.

                appLog.info('Data was returned and more data is available. Trying again immediately', extra={'date_time' : time.strftime("%b %d %H:%M:%S", time.gmtime(time.time()))})
                # Update the token to the new value
                wss.token=wss.xSyncToken
                coolOffPeriod=DELAY_MORE_DATA_AVAILABLE

            elif wss.xSyncStatus == 'abor':
                # Data was returned and more data is available after the WSS issue is
                # resolved. The service experienced an internal issue while building
                # the ZIP archive. Much of the download might be usable, except for the
                # last file in the archive. The client might begin a new session by
                # requesting a new start date without a token. Otherwise, the client
                # reuses the same dates and token until the download is successful.
                appLog.critical('WSS ISSUE - Data was returned and more data is available after the WSS issue is resolved', extra={'date_time' : time.strftime("%b %d %H:%M:%S", time.gmtime(time.time()))})
                coolOffPeriod=DELAY_WSS_ERROR

            elif wss.xSyncStatus == 'done':
                if wss.xSyncToken == wss.token:
                    # No data was returned and no more data is available. If a date range
                    # was given, the WSS found no data within the range. If no end date
                    # was given, the client pauses before polling for new data. If polling, the
                    # client reuses the same token until a new token is provided.

                    if wss.endDate == 0:
                        appLog.info('No data was returned and no more data is available', extra={'date_time' : time.strftime("%b %d %H:%M:%S", time.gmtime(time.time()))})
                        coolOffPeriod=DELAY_NO_MORE_DATA_AVAILABLE
                    else:
                        appLog.info('No data was found within the date range specified', extra={'date_time' : time.strftime("%b %d %H:%M:%S", time.gmtime(time.time()))})
                        coolOffPeriod=0
                        break
                else:
                    # Data was returned and no more data is available. If an end date was
                    # given, the download is complete. If no end date was given, the client
                    # pauses before polling for new data. The client provides the new token
                    # in the next request.

                    # Update the token to the new value
                    wss.token=wss.xSyncToken

                    if wss.endDate == 0:                    
                        appLog.info('Data was returned and no more data is available', extra={'date_time' : time.strftime("%b %d %H:%M:%S", time.gmtime(time.time()))})
                        coolOffPeriod=DELAY_NO_MORE_DATA_AVAILABLE
                    else:
                        appLog.info('Download completed', extra={'date_time' : time.strftime("%b %d %H:%M:%S", time.gmtime(time.time()))})
                        coolOffPeriod=0
                        break                                
            else:
                appLog.critical('Unrecognised wss.xSyncStatus value: %s', wss.xSyncStatus, extra={'date_time' : time.strftime("%b %d %H:%M:%S", time.gmtime(time.time()))})
                coolOffPeriod=DELAY_WSS_ERROR
        else:
            # The download was NOT successful. i.e. status_code does not equal 200
            # Need to inspect the returned error code to determine the next course of action.          
            if wss.response.status_code == 400:
                appLog.critical('Response error code %i - BAD REQUEST - The start date is later than the end date; bad syntax; or some other request error. The client verifies it is properly using the Sync API.', wss.response.status_code, extra={'date_time' : time.strftime("%b %d %H:%M:%S", time.gmtime(time.time()))})
                coolOffPeriod=DELAY_WSS_ERROR

            elif wss.response.status_code == 403 or wss.response.status_code == 401:
                appLog.critical('Response error code %i - UNAUTHORISED or FORBIDDEN - Likely the API keys are incorrect', wss.response.status_code, extra={'date_time' : time.strftime("%b %d %H:%M:%S", time.gmtime(time.time()))})
                coolOffPeriod=DELAY_WSS_ERROR

            elif wss.response.status_code == 410:
                appLog.warning('Response error code %i - GONE - The token is no longer within the given dates or the token references expired data and the tokens associated WSS data is no longer available. The token is no longer valid and is discarded. The client might obtain a new token by requesting a new start date without a token.', wss.response.status_code, extra={'date_time' : time.strftime("%b %d %H:%M:%S", time.gmtime(time.time()))})
                appLog.info('Setting Token to none', extra={'date_time' : time.strftime("%b %d %H:%M:%S", time.gmtime(time.time()))})
                wss.token = 'none'
                wss.startDate = WSS_TIME_OF_LAST_LOG_DOWNLOADED
                coolOffPeriod=0

            elif wss.response.status_code == 429:
                appLog.warning('Response error code %i - TOO MANY REQUESTS - The WSS is unwilling to service the client until a reasonable time has elapsed. The Retry-After field shows the remaining wait period in seconds. The default is expected to be around five (5) minutes.', wss.response.status_code, extra={'date_time' : time.strftime("%b %d %H:%M:%S", time.gmtime(time.time()))})
                coolOffPeriod=int(wss.response.headers['Retry-After'])+2

            elif wss.response.status_code == 500:
                appLog.warning('Response error code %i - INTERNAL ERROR - An internal WSS error prevented the download. The client might need to wait a while before repeating the request.', wss.response.status_code, extra={'date_time' : time.strftime("%b %d %H:%M:%S", time.gmtime(time.time()))})
                coolOffPeriod=DELAY_WSS_ERROR

            elif wss.response.status_code == 503:
                appLog.warning('Response error code %i - Service Unavailable - No resources are currently available to service the request; or a WSS component is temporarily offline. The service might restrict the total number of downloads currently in progress. The client waits before repeating the request.', wss.response.status_code, extra={'date_time' : time.strftime("%b %d %H:%M:%S", time.gmtime(time.time()))})
                coolOffPeriod=DELAY_WSS_ERROR

            else:
                appLog.critical('Response error code %i - Unknown error', wss.response.status_code, extra={'date_time' : time.strftime("%b %d %H:%M:%S", time.gmtime(time.time()))})

        if wss.token != WSS_LAST_TOKEN_RECEIVED:
            WSS_LAST_TOKEN_RECEIVED=wss.token # Set the WSS_LAST_TOKEN_RECEIVED as this is what is saved to the config file
            appLog.info('Updating config file: %s with last_token_received: %s', cli_args.parse_args().c, WSS_LAST_TOKEN_RECEIVED, extra={'date_time' : time.strftime("%b %d %H:%M:%S", time.gmtime(time.time()))})
            appLog.info('Updating config file: %s with last_successful_download: %s', cli_args.parse_args().c, WSS_TIME_OF_LAST_LOG_DOWNLOADED, extra={'date_time' : time.strftime("%b %d %H:%M:%S", time.gmtime(time.time()))})
            conf.save(cli_args.parse_args().c)

    appLog.info('Pausing for %i seconds before retrying', coolOffPeriod, extra={'date_time' : time.strftime("%b %d %H:%M:%S", time.gmtime(time.time()))})
    time.sleep(coolOffPeriod)

#Should never get here unless both a start and end date were specified and there is no more data to be downloaded
appLog.critical('%s - Quitting', __file__, extra={'date_time' : time.strftime("%b %d %H:%M:%S", time.gmtime(time.time()))})
raise SystemExit
#!/usr/bin/env python

import sys
import multiprocessing
import os
import signal
import logging
from optparse import OptionParser
import capd_proxy

class WatchDog(object):
    '''
    Watchdog class that creates and manages the Experiment Manager
    ''' 
    def __init__(self, logger, port, host, debug, basedir, defaultdev, capdexec):
        self.running = True
        self.pid = 0
        self.logger = logger
        self.port = port
        self.host = host
        self.debug = debug
        self.basedir = basedir
        self.defaultdev = defaultdev
        self.capdexec = capdexec 
              
        #install signal handlers after experiment manager starts
        signal.signal(signal.SIGINT, self.sigIntProxy)
        signal.signal(signal.SIGTERM, self.sigIntProxy)
        signal.signal(signal.SIGPIPE, signal.SIG_IGN)
        signal.signal(signal.SIGHUP, signal.SIG_IGN) 
     
        self.startCapdProxy()
        
    def startCapdProxy(self):
        '''
        Ensures Proxy is running in case of a crash, also stops it
        if it is running for too long. 
        '''
        p = None

        while self.running:
        #keep checking if capture proxy has died
            if not p or not p.is_alive():
                p = multiprocessing.Process(target=capd_proxy.proxy_main, args=(self.port, self.host, self.debug, self.basedir, self.defaultdev, self.capdexec))
                self.logger.info('Starting Capture Proxy.')
                p.start()
                self.pid = p.pid
       
            p.join(120)    

    def sigIntProxy(self, signum, stackframe):
        '''
        Handler function to propagate termination signal to capd_proxy
        '''
        self.logger.info('Termination signal sent to Experiment Manager') 
        os.kill(self.pid, signal.SIGTERM)
        self.running = False
 
def main():

    parser = OptionParser()
    parser.add_option("-p", "--port", dest="port", default=8001,
                      type="int", action="store", help="Set XML/RPC listen port")
    parser.add_option("-l", "--host", dest="host", default="0.0.0.0",
                      action="store", help="Set host/IP to which XML/RPC listener is bound")
    parser.add_option("-x", "--debug", dest="debug", default=False,
                      action="store_true", help="Turn on debugging output")
    parser.add_option("-b", "--basedir", dest="basedir", default="./capdata",
                      help="Set the base directory for output measurements")
    parser.add_option("-d", "--device", dest="defaultdevice", default="eth0",
                      help="Set the default capture device")
    parser.add_option("-c", "--capdaemon", dest="capdexec", 
                      # default="./fake-capture-daemon",
                      default="./capture-daemon/capture-daemon",
                      help="Set the path to the capture-daemon executable")
    (options, args) = parser.parse_args()    

    if options.debug:
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(name)-14s %(levelname)-8s %(message)s', filename='watch_proxy.log')
    else:
        logging.basicConfig(level=logging.INFO, format='%(asctime)s %(name)-14s %(levelname)-8s %(message)s', filename='watch_proxy.log')
      
    console = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s %(name)-14s %(levelname)-8s %(message)s')
    console.setFormatter(formatter)
    logging.getLogger('').addHandler(console)
    
    logger = logging.getLogger('watch_proxy')
    
    logger.info('Watchdog starting up.')
    watchdog = WatchDog(logger, options.port, options.host, options.debug, options.basedir, options.defaultdevice, options.capdexec)
    	  
if __name__ == '__main__' :
    main()        
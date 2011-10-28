#!/usr/bin/env python

__author__ = 'jsommers@colgate.edu'
__doc__ = '''
Capture daemon proxy server to handle XML/RPC calls from GIMS UI-side process. 
Handles managing experiment state, starting, configuring, and stopping
capture processes, and managing data upload.

This source code is licensed under the GENI public license.
See www.geni.net, or "geni_public_license.txt" that should 
have accompanied this software.
'''


import sys
from SimpleXMLRPCServer import SimpleXMLRPCServer
from SimpleXMLRPCServer import SimpleXMLRPCRequestHandler
import xmlrpclib
from optparse import OptionParser
import multiprocessing
import Queue
import re
import os
import datetime
import signal
import time
import logging
import random
import StringIO
import resource
import xml.etree.ElementTree
import capd_storage

# the lone global variable; flag to tell whether we should quit the
# program or not.
running = True


class RequestHandler(SimpleXMLRPCRequestHandler):
    '''
    Overridden base xmlrpc request handler.  Just modify the logging
    to flow into our own logger.
    '''
    rpc_paths = ('/RPC2', '/')

    def log_message(self, format, *args):
	'''
	Logs the message given in args in a particular format.
	'''
        pre = 'xmlrpc request from ' + self.address_string() + ' '
        xstr = format % (args)
        logger = logging.getLogger('capd_proxy')
        logger.debug(pre + xstr)


class ExperimentState(object):
    '''
    Container class to encapsulate information about an individual
    experiment.
    '''
    def __init__(self, exptname, xdir):
	'''
	Set default attribute values only.

	exptname -- Name of experiment
	xdir -- Experiment Directory to use
	~Also initializes capture_on, capture_pid, config, capture_start,
	timeidle and  proc to default values~	
	'''

        self.experiment_name = exptname
        self.capture_on = False
        self.capture_pid = -1
        self.config = dict()
        self.exptdir = xdir
        self.capture_start = None
        self.timeidle = time.time()
        self.proc = None

    def getId(self):
	'''
	Returns experiment_name.
	'''
        return self.experiment_name

    def getAge(self):
	'''
	Returns time the experiment has spent running.
	'''
        if self.capture_on:
            return 0
        return int(time.time() - self.timeidle)

    def setConfig(self, key, value):
	'''
	Modifiess the current configuration of the Experiment.
	ie setConfig('anonkey', 'abc')

	key -- Key to modify in the config dictionary
	value -- Value to modify or set in the config dictionary
	'''
        self.config[key] = value

    def getConfig(self, key):
	'''
	Returns the configuration of the experiment.

	key -- Return value associated with given key
	'''
        return self.config.get(key, None)

    def clean(self):
	'''
	Kills the capture process associated with the experiment if not on.
	'''
        if self.capture_on and self.capture_pid > 0:
            os.kill(pid, signal.SIGINT)
 
    def setActive(self, b, pid):
	'''
	Sets the active capturing process PID and modifies the timestamps.

	b -- Starts capturing
	pid -- PID for capture daemon process associated with the current experiment
	'''
        self.capture_start = time.time()
        self.timeidle = time.time()
        self.capture_on = b
        self.capture_pid = pid

    def getActive(self):
	'''
	Returns capture_on.
	'''
        return self.capture_on

    def __str__(self):
	'''
	Returns a string representation of the experiment object, along with
	the user configuration and current status.
	'''
        rv = 'Experiment: ' + self.experiment_name + ' :-: '
        kvlist = []
        for k,v in self.config.items():
            kvlist.append(k + '->' + str(v))
        rv += ':::'.join(kvlist)
        rv += ' :-: capture on ' + str(self.capture_on)
        rv += ' :-: capture pid ' + str(self.capture_pid)
        return rv

    def getStorageInfo(self):
	'''
	Returns the type of storage being used in the experiment (local, s3, snmp), 
	the experiment directory and a tuple containing the credentials for the
	particular type of storage.
	'''
        stype = 'local'
        stup = (None,)
        
        if 'sshuser' in self.config and 'sshhost' in self.config and 'sshkey' in self.config:
            stype = 'ssh'
            slist = []
            slist.append(self.config['sshuser'])
            slist.append(self.config['sshhost'])
            slist.append(self.config['sshkey'])
            if 'sshpath' in self.config:
                slist.append(self.config['sshpath']+'/')
            else:
                slist.append('./')
            if 'sshport' in self.config:
                slist.append(self.config['sshport'])
            else:
                slist.append(22)
            stup = tuple(slist)
            
        elif 's3key' in self.config and 's3secret' in self.config and 's3bucket' in self.config:
            stype = 's3'
            stup = (self.config['s3key'], self.config['s3secret'], self.config['s3bucket'])

        return stype, self.exptdir, stup
        

class ExperimentManager(object):
    '''
    The main class of this program: all the xmlrpc methods are defined
    here, and all the important state is stored here.
    '''

    def __init__(self, logger, debug, basedir, defaultdev, capdexec, tmo=21600):
	'''
	Set default attribute values, creates a dummy file for testing upload and installs
	special signal handlers after storage processes have been started.

	logger -- Logger used for the manager.
	debug -- Boolean to run capd_proxy in debug mode.
	basedir -- Directory to use for the Experiment Manager
	defaultdev -- Ethernet device to be used
	capdexec -- Capturing device to used.
	tmo=21600 --  *FIXME*
	'''
        self.exptdb = dict()
        self.piddb = dict()
        self.logger = logger
        self.debug = debug
        self.basedir = basedir
        self.defaultdev = defaultdev
        self.capdexec = capdexec
        self.testfile = 'GIMStestfile.txt'
        self.expttimeout = tmo

        # create file for testing uploads
        tout = open(self.testfile, 'w')
        print >>tout, "This is a dummy file for testing uploads."
        tout.close()

        # install special signal handlers after storage
        # processes have been started
        signal.signal(signal.SIGINT, self.sigInt)
        signal.signal(signal.SIGTERM, self.sigInt)
        signal.signal(signal.SIGPIPE, signal.SIG_IGN)
        signal.signal(signal.SIGHUP, signal.SIG_IGN)

        self.storage_daemon = None
        self.startStorageAgent()


    def startStorageAgent(self):
	'''
	Starts the storage_agent as a separate process.
	'''
        toc,fromc = multiprocessing.Queue(),multiprocessing.Queue()
        p = multiprocessing.Process(target=capd_storage.storage_agent, args=(toc, fromc, self.basedir, self.debug))
        self.storage_daemon = (p, toc, fromc)
        p.start()

        
    def stopStorageAgents(self):
	'''
	Stops the storage agent and writes on the log.
	'''
        self.logger.info("Stopping storage agent.")
        self.storage_daemon[1].put(('STOP',))
        try:
            self.storage_daemon[0].terminate()
            self.storage_daemon[0].join(1)
        except OSError,e:
            pass
        self.logger.debug("After stopping storage agent.")


    def sigInt(self, signum, stackframe):
	'''
	Changes the state of the program to not running and writes to the log.
	'''
	global running
        self.logger.info('Caught sig %d in RPC listener.  Going down.' % (signum))
        running = False

    def maintenance(self):
	'''
	Gets rid of the experiments whose age is greater than the timeout, meaning they shouldn't be running.
	'''
        deadexpts = []
        for eid,exptstate in self.exptdb.items():
            if exptstate.getAge() > self.expttimeout:
                self.logger.info('Cleaning up stale experiment state for ' + eid + ' ' + str(exptstate))
                exptstate.clean()
                deadexpts.append(eid)
        for eid in deadexpts:
            del self.exptdb[eid]


    def getState(self):
	'''
	Reutrns current state of experiment.
	'''
        outstr = 'Experiments:\n'
        for k,v in self.exptdb.items():
            outstr += str(k) + ' ' + str(v) + '\n'
        return outstr


    def TestExperimentStorage(self, params):
        '''
        Alias for testExperimentStorage

	 params -- exptid (string)
        '''
	return self.testExperimentStorage(params)


    def testExperimentStorage(self, params):
        '''
        Test whether experiment storage settings result in
        correct uploading.

        params -- exptid (string) 
	 return -- response string, or xmlrpc.fault on error
        '''
        self.maintenance()
        self.checkParams('startExperiment', params)

        exptid = self.getExptId(params)

        if exptid not in self.exptdb:
            self.logger.info('Throwing exception: no such experiment: '+exptid)
            raise xmlrpclib.Fault(-1, 'No such experiment '+exptid+' exists')
        self.logger.info('Attempt to test storage for experiment %s' % (exptid))

        expt = self.exptdb[exptid]
        self.checkSufficientConfig(expt) 
        
        stype,xdir,stup = expt.getStorageInfo()
        self.logger.info('Testing storage %s for experiment %s cred(%s)' % (stype, expt.getId(), str(stup)))


        flist = [(self.testfile, self.testfile)]

        try:
            response = 'Local storage ok.'
            if stype == 's3':
                capd_storage.s3_upload('./', self.logger, exptid, stup[0], stup[1], stup[2], flist)
                response = 's3 storage appears to work.  please verify upload of GIMStestfile.txt'
            elif stype == 'ssh':
                xdir = './'
                if stup[3]:
                    xdir = stup[3] + '/'
                capd_storage.sftp_upload('./', self.logger, exptid, stup[1], stup[0], stup[2], flist, stup[3] + os.sep, stup[4])
                response = 'ssh storage appears to work.  please verify upload of GIMStestfile.txt'
            elif stype == 'local':
                local_upload('./', self.logger, exptid, flist)
        except Exception,e:
            raise xmlrpclib.Fault(-1, 'Error while testing storage: '+str(e))

        self.logger.info('Storage test result for %s: %s' % (exptid, response))
        return response
      


    def StartExperiment(self, params):
        '''
        Alias for startExperiment.
        '''
        return self.startExperiment(params)


    def startExperiment(self, params):
        '''
	 Starts the experiment.
	
        params -- exptid (string) 
	 return -- response string or xmlrpc.Fault on error
        '''

        self.maintenance()
        self.checkParams('startExperiment', params)

        exptid = self.getExptId(params)

        if exptid not in self.exptdb:
            self.logger.info('Throwing exception: no such experiment: '+exptid)
            raise xmlrpclib.Fault(-1, 'No such experiment '+exptid+' exists')
        self.logger.info('Attempt to start experiment %s' % (exptid))

        expt = self.exptdb[exptid]
        if expt.getActive():
            self.logger.info('Throwing exception: experiment already started: '+exptid)
            raise xmlrpclib.Fault(-1, "Experiment already started: "+exptid)

        self.checkSufficientConfig(expt)
        pid = self.doStartExperiment(expt)
        return ''.join(['Successfully started experiment ',exptid,'.  Process id ',str(pid)])


    def PauseExperiment(self, params):
        '''
        Alias for pauseExperiment
        '''
        return self.pauseExperiment(params)


    def pauseExperiment(self, params):
        '''
	 params -- exptid(string)
        return: response string or xmlrpc.Fault
        '''

        self.maintenance()
        self.checkParams('pauseExperiment', params)

        exptid = self.getExptId(params)
        if exptid not in self.exptdb:
            self.logger.info('Throwing exception: no such experiment: '+exptid)
            raise xmlrpclib.Fault(-1, 'No such experiment '+exptid+' exists')

        self.logger.info('Attempt to pause capture for experiment %s' % (exptid))

        expt = self.exptdb[exptid]
        pid = self.doStopExperiment(expt, notifyStorage=False)

        return ''.join(['Successfully paused capture for experiment ',exptid,', process id',str(pid)])
        

    def ResumeExperiment(self, params):
        '''
        Alias for resumeExperiment
        '''
        return self.resumeExperiment(params)


    def resumeExperiment(self, params):
        '''
        Alias for startExperiment.
        '''
        return self.startExperiment(params)


    def StopExperiment(self, params):
        '''
        Alias for stopExperiment.
        '''
        return self.stopExperiment(params)


    def stopExperiment(self, params):
        '''
	 Stops the experiment by joining any child processes with a particular expid.

        params -- exptid(string)
	 return -- response string or xmlrpc.Fault
        '''
        self.maintenance()
        self.checkParams('stopExperiment', params)

        exptid = self.getExptId(params)
        if exptid not in self.exptdb:
            self.logger.info('Throwing exception: no such experiment: '+exptid)
            raise xmlrpclib.Fault(-1, 'No such experiment '+exptid+' exists')

        self.logger.info('Attempt to stop experiment %s' % (exptid))

        expt = self.exptdb[exptid]
        pid = self.doStopExperiment(expt, notifyStorage=True)
        return ''.join(['Successfully stopped experiment ',exptid,', process id',str(pid)])


    def GetStorageLog(self, params, n):
        '''
        Alias for getStorageLog.
        '''
        return self.getStorageLog(params, n)

    def getStorageLog(self, params, n):
        '''
        
	 
	 params: exptid (string)
        return: n last storage log entries for a particular experiment or general errors with exptid GEN
        xmlrpc.Fault
        '''
        self.maintenance()
        self.checkParams('getStorageLog', params)
        
        exptid = self.getExptId(params)
        if exptid not in self.exptdb:
            self.logger.info('Throwing exception: no such experiment: '+exptid)
            raise xmlrpclib.Fault(-1, 'No such experiment '+exptid+' exists')

        self.logger.info('Attempt to obtain storage info %s' % (exptid))
        storage_log = './' + os.sep + 'storage_agent.log'
        outstr = ""
        
        #Open storage_agent.log and get the last n log entries for given Experiment ID
        h = n 
        try:
            slog = open(storage_log, 'r')
            temp = reversed(slog.readlines())
            for line in temp:
                if (n <= 0):
                    break
                else:
                    msg = line.strip().split()
                    if (msg[4] == exptid):
                        outstr = " ".join(msg[0:]) + "\n" + outstr
                        n = n-1            
        except:                
            self.logger.warn("Attempted to read storage log on experiment " + exptid + " but storage log file doesn't exist ('storage_agent.log')")

        return "Last " + str(h) + " log lines:\n" + outstr


    def GetExperimentStats(self, params):
        '''
        Alias for getExperimentStats.
        '''
        return self.getExperimentStats(params)


    def getExperimentStats(self, params):
        '''
	 Returns the latest stats of the experiment specified in params.

        params -- exptid (string)
 	 return -- all expt params + CaptureStats (as a string) or
        xmlrpc.Fault
        '''
        self.maintenance()
        self.checkParams('getExperimentStats', params)

        exptid = self.getExptId(params)
        if exptid not in self.exptdb:
            self.logger.info('Throwing exception: no such experiment: '+exptid)
            raise xmlrpclib.Fault(-1, 'No such experiment '+exptid+' exists')

        self.logger.info('Attempt to obtain experiment info %s' % (exptid))

        expt = self.exptdb[exptid]

        outstr = "exp_id: " + expt.experiment_name + "\n"
        stype,xdir,stup = expt.getStorageInfo()
        outstr += "storage_type: " + stype + "\n"

        if stype == 'ssh':
            xname = ['user','host','key','path','port']
            xlist = list(stup)
            xlist[2] = '(key hidden)'
            xstr = 'unable to obtain params'
            try:
                xstr = ','.join([ xname[i] + '=' + str(xlist[i]) for i in xrange(5) ])
            except:
                pass
            outstr += "storage_params: " + xstr + "\n"
        elif stype == 's3':
            outstr += "storage_params: (key and secret not shown) s3bucket=" + stup[-1] + "\n"

        outstr += "local_staging_folder: " + xdir + "\n"

        r = resource.getrusage(resource.RUSAGE_CHILDREN)
        outstr += "memory_consumed: " + str(r.ru_maxrss) + "kB \n"
        outstr += "cpu_time_user: %3.3f" % (r.ru_utime) + "\n"
        outstr += "cpu_time_system: %3.3f" % (r.ru_stime) + "\n"

        outstr += "capture_enabled:" + str(expt.capture_on) + "\n"

        if expt.capture_on:
            outstr += "capture_started: " + time.strftime("%Y/%m/%d-%H:%M:%S",time.localtime(expt.capture_start)) + "\n"
            outstr += "capture_pid: " + str(expt.capture_pid) + "\n"

            temp = 'stats_' + str(exptid) + '.txt'
            try:    
                fd = open(temp,'r')
                fields = fd.read().strip().split()
                bytes, pkts, sbytes, spkts, nfiles = fields[1::2]
                
                outstr += "bytes_observed: " + str(bytes) + "\n"
                outstr += "packets_observed: " + str(pkts) + "\n"
                outstr += "bytes_after_sampling: " + str(sbytes) + "\n"
                outstr += "packets_after_sampling: " + str(spkts) + "\n"
                outstr += "files_written: " + str(nfiles) + "\n"
                fd.close()
            except:
                self.logger.warn('Attempted to read temporary stats file: ' + temp + ' but stats file does not exist')

        captured,uploaded = self.getNumUploaded(exptid)
        outstr += "files_uploaded: " + str(uploaded) + "\n"

        return outstr


    def getNumUploaded(self, exptid):
        '''
        Find the number of files written by the capture system and
        the number of files/bytes transferred to storage by the
        capture system.

	 exptid -- Experiment ID
        '''
        completed_upload = './' + os.sep + 'completed_upload.txt'
        completed_capture = './' + os.sep + 'completed_capture.txt'

        numcapture = 0
        numupload = 0

        try:
            fin = open(completed_capture, 'r')
            for line in fin:
                xexpt, metafile = line.strip().split()

                if xexpt == exptid:
                    numcapture += 1
            fin.close()
        except:
            #self.logger.warn("Attempted to read file upload stats on experiment " + exptid + " but stats tracking file doesn't exist ('completed_capture.txt')")
            pass

        try:
            fin = open(completed_upload, 'r')
            for line in fin:
                xexpt, fname, stype, datestamp = line.strip().split()
                if xexpt == exptid:
                    numupload += 1
            fin.close()
        except:
            #self.logger.warn("Attempted to read file upload stats on experiment " + exptid + " but stats tracking file doesn't exist ('completed_upload.txt')")
            pass

        return numcapture,numupload


    def ConfigureExperiment(self, params):
        '''
        Alias for configureExperiment.
        '''
        return self.configureExperiment(params)


    def configureExperiment(self, params):
        '''
	 Configures the experiment by calling the doConfig method and initializes the 
        various parameters passed in params.

        params -- exptid (string), --many other params-- (see doConfig)
	 return -- status (string) or xmlrpc.Fault on error
        '''
        self.maintenance()
        self.checkParams('configureExperiment', params)

        exptid = self.getExptId(params)
        self.logger.debug('Configure experiment %s' % (exptid))
        if exptid not in self.exptdb:
            estate = ExperimentState(exptid, self.basedir + os.path.sep + exptid)
            self.exptdb[exptid] = estate
            self.logger.info(' '.join(['New experiment state created for',str(exptid),str(params)]))

        expt = self.exptdb[exptid]
        warnings = self.doConfig(expt, params)
        wstr = 'Success'
        if len(warnings):
            wstr = ':::'.join(warnings)
        self.logger.info('Configure experiment %s.  Current state: %s; config warnings: %s' % (exptid, str(expt), wstr))
        return ''.join(['Successfully configured experiment ',exptid,'. Current state: ',str(expt),'.  Configuration warnings: ',wstr])

    
    def checkParams(self, methodname, params):
	'''
	Checks wheter the parameters are defined and raise an exception otherwise.
	
	methodname -- Method Name to check
	params -- Dictionary containing the parameters for the experiment
	'''

        if not self.getExptId(params):
            self.logger.info('Throwing exception: no experiment specified')
            raise xmlrpclib.Fault(-1, 'Missing \'ExperimentId\' in parameter structure')
        if methodname == 'startExperiment':
            return None 
        elif methodname == 'stopExperiment':
            return None 
        elif methodname == 'configureExperiment':
            return None 
        elif methodname == 'getExperimentStats':
            return None
        elif methodname == 'getStorageLog':
            return None 
        elif methodname == 'pauseExperiment':
            return None 
        elif methodname == 'resumeExperiment':
            return None 
        else:
            self.logger.info('Throwing exception: invalid method name')
            raise xmlrpclib.Fault(-1, 'Invalid method name in checkParams')
    

    def checkSufficientConfig(self, exptstate):
	'''
	Checks wheter enough information has been given to start an experiment.

	exptstate -- Object containing the experiment state. (see Experiment State Class)
	'''
        if not exptstate.getId():
            self.logger.info('Throwing exception: missing experiment id')
            raise xmlrpclib.Fault(-1, 'Missing Experiment Id')
        stype = exptstate.getConfig('storage')
        if not stype:
            self.logger.info('Throwing exception: no storage configuration')
            raise xmlrpclib.Fault(-1, 'No storage configuration')
        if stype == 's3':
            if not exptstate.getConfig('s3key'):
                raise xmlrpclib.Fault(-1, 'Missing s3 access key')
            elif not exptstate.getConfig('s3secret'):
                raise xmlrpclib.Fault(-1, 'Missing s3 secret key')
            elif not exptstate.getConfig('s3bucket'):
                raise xmlrpclib.Fault(-1, 'Missing s3 bucket name')
        elif stype == 'ssh':
            if not exptstate.getConfig('sshuser'):
                raise xmlrpclib.Fault(-1, 'Missing SSH user')
            elif not exptstate.getConfig('sshhost'):
                raise xmlrpclib.Fault(-1, 'Missing SSH hostname')
            elif not exptstate.getConfig('sshkey'):
                raise xmlrpclib.Fault(-1, 'Missing SSH private key')
        stype = exptstate.getConfig('sampletype')
        if stype and stype != 'none':
            sparm = exptstate.getConfig('sampleparam')
            if not sparm:
                raise xmlrpclib.Fault(-1, 'Missing sample parameter')
        atype = exptstate.getConfig('anontype')
        if atype and atype != 'none':
            aparm = exptstate.getConfig('anonkey')
            if atype != 'anonymize' or not aparm:
                # FIXME: need to really raise the error; need a key!
                exptstate.setConfig('anonkey', 'abcdabcdabcdabcd')
                # raise xmlrpclib.Fault(-1, 'Incomplete anonymization configuration')
        return None
    
    
    def constructCommandLine(self, exptstate):
	'''
	Builds a set of command line options, to support sampling, aggregation, different devices and
	different VLAN. It obtains data from the Experiment Configuration and puts in cmdlist.

	expstate -- Object containg experiment state
	'''

        cmdlist = [ self.capdexec ]
        # !hack alert! unconditionally set the device to defaultdev
        #if exptstate.getConfig('device'):
        #    cmdlist.append("-d")
        #    cmdlist.append(exptstate.getConfig('device'))
        #elif len(self.defaultdev):
        #    cmdlist.append('-d')
        #    cmdlist.append(self.defaultdev)
        cmdlist.append('-d')
        cmdlist.append(self.defaultdev)

        filterexpr = ''
        if exptstate.getConfig('vlan'):
            xvlan = -1
            try:
                xvlan = int(exptstate.getConfig('vlan'))
            except:
                pass
            if xvlan > 0: 
                filterexpr += 'vlan ' + str(exptstate.getConfig('vlan'))
        if exptstate.getConfig('filterexpr'):
            if len(filterexpr):
                filterexpr += ' and'
            filterexpr += ' ' + exptstate.getConfig('filterexpr')
        if len(filterexpr):
            cmdlist.append('-s')
            cmdlist.append(filterexpr)

        outdir = self.basedir + os.path.sep + exptstate.getId()
        self.logger.debug('Making output directory: '+outdir)
        try:
            os.makedirs(outdir)
        except OSError,e:
            if 'File exists' in str(e):
                pass
            else:
                self.logger.error('Error making temp storage pen: ' + str(e))
                raise xmlrpclib.Fault(-1, 'Error making local storage for capture files:' + str(e))
                
        cmdlist.append('-p')
        cmdlist.append(outdir)

        siteloc = exptstate.getConfig('sitelocation')
        if siteloc:
            cmdlist.append('-l')
            cmdlist.append(siteloc)

        metatext = exptstate.getConfig('metatext')
        configname = exptstate.getConfig('configname')
        if metatext or configname:
            cmdlist.append('-u')
            xstr = ''
            if configname:
                xstr = '='.join(['configname',configname])
            if metatext:
                xstr = ';'.join([xstr,metatext])
            cmdlist.append(xstr)

        cmdlist.append('-N')
        cmdlist.append(exptstate.getId())

        #SAMPLING
        samptype = exptstate.getConfig('sampletype')
        if samptype and samptype != 'none':
            cmdlist.append('-t')
            if samptype == 'everyN':
                cmdlist.append('3')
            elif samptype == 'uniformrandom':
                cmdlist.append('2')
            cmdlist.append('-r')
            sampparam = exptstate.getConfig('sampleparam')
            cmdlist.append(sampparam)

        #ANONYMIZATION
        anontype = exptstate.getConfig('anontype')
        if anontype and anontype != 'none':
            cmdlist.append('-k')
            anonkey = exptstate.getConfig('anonkey')
            cmdlist.append(anonkey)

        #AGGREGATION
        aggtype = exptstate.getConfig('aggregationtype')
        if aggtype and aggtype != 'none':
            cmdlist.append('-a')
            if aggtype == 'count_pkts':
                cmdlist.append('count')
            elif aggtype == 'combine_pkt_flows':
                cmdlist.append('flow')

        #FILE ROLLOVER PERIOD
        cmdlist.append('-z')
        rolloverint = exptstate.getConfig('rollover')
        if rolloverint:
            cmdlist.append(str(int(rolloverint)*60))
        else:
            cmdlist.append('30') # default to 30 seconds

        # ensure that everything is a string that we pass
        # to the cmd line.
        cmdlist = [ str(x) for x in cmdlist ]

        return self.capdexec, outdir, cmdlist
    
    
    def notifyStorageStart(self, exptstate):
	'''
	Registers a new experiment with the Storage.

	exptstate -- Experiment Object containg all states of an experiment.
	'''
        stype,xdir,stup = exptstate.getStorageInfo()
        q = self.storage_daemon[1]
        self.logger.info('Notifying storage agent about experiment %s (%s)' % (exptstate.getId(), stype))
        q.put( ('NEWEXPT', exptstate.getId(), stype, stup, xdir) )


    def notifyStorageStop(self, exptstate):
	'''
	Notifies the Storage that an experiment has stopped.
	
	exptstate -- Experiment Object containg all states of an experiment.
	'''
        stype,xdir,stup = exptstate.getStorageInfo()
        q = self.storage_daemon[1]
        self.logger.info('Notifying storage to finish experiment %s (%s)' % (exptstate.getId(), stype))
        q.put( ('RMEXPT', exptstate.getId(), stype, stup, xdir) )


    def reapChildren(self):
        '''
	 Joins all remaining child processes from capd_proxy.
        '''
        deadpids = []
        for pid in self.piddb:
            exptstate = self.piddb[pid]
            if exptstate.proc and not exptstate.proc.is_alive():
                self.logger.debug('Reaping child process %d' % (pid))
                deadpids.append(pid)
                exptstate.setActive(False, -1)
                exptstate.proc.join()
                exptstate.proc = None
        for pid in deadpids:
            del self.piddb[pid]


    def _capdentry(self, path, args):
        '''
        Entrypoint for capture daemon binary startup

	 path -- Location of the process to be started to take over capd_proxy process space. 
	 args -- Arguments required for the process located in path to be started.
        '''
        try:
            os.execv(path, args)
        except OSError,e:
            self.logger.warn('Child process failed to start: %s' % (str(e)))


    def doStartExperiment(self, exptstate):
        '''
        Start an experiment.  Assumes that configuration has been checked
        for sufficiency.

	 exptstate -- Experiment Object containg all states of an experiment.
        '''

        path,outdir,args = self.constructCommandLine(exptstate)

        self.notifyStorageStart(exptstate)
        self.logger.info('Starting experiment: %s // %s // %s' % (path,outdir,str(args)))

        p = multiprocessing.Process(target=self._capdentry, args=(path, args))
        p.start()

        # experiment has started up
        if not p.is_alive():
            self.logger.info('Throwing exception: cannot spawn capture process: ' + str(e))
            raise xmlrpclib.Fault(-1, 'Couldn\'t spawn capture process for experiment %s: %s' % (exptstate.getId(), str(e)))
        exptstate.proc = p
        exptstate.setActive(True, p.pid)
        self.piddb[p.pid] = exptstate
        return p.pid

    
    def doStopExperiment(self, exptstate, notifyStorage=True):
        '''
        Stop an experiment.  Assumes that configuration has been checked
        for sufficiency.

	 exptstate -- Experiment Object containg all states of an experiment.
	 notifyStorage -- Assumes that this method has already been called on the expstate object.
        '''
        pid = exptstate.proc.pid
        if pid > 0:
            self.logger.info('Sending SIGTERM to capture process %d.' % (pid))
            exptstate.proc.terminate()
            exptstate.setActive(False, -1)
            return
        else:
            exptstate.setActive(False, -1)
            raise xmlrpclib.Fault(-1, 'Experiment is not running')

        # notify storage only if we're *stopping* the experiment,
        # not just pausing it.
        if notifyStorage:
            self.notifyStorageStop(exptstate)

        return pid

    
    def getExptId(self, params):
        '''
 	 Returns Experiment Id

	 params -- exptid (string)
        '''

        rv = None
        if 'ExperimentId' in params:
            rv = params['ExperimentId'] 
        elif 'ExperimentID' in params:
            rv = params.pop('ExperimentID')
            params['ExperimentId'] = rv
        return rv
    
    
    def doStorageConfig(self, exptstate, xdict):
        '''
        StorageSpec (struct)
           storagetype (string) ("local", "s3", "ssh")
           storageparams (struct)
                local: local_storage_dir
                s3: s3accesskey: string, s3secretkey: string, s3bucket: string
                ssh: sshuser: string, sshhost: string, sshport: int, sshpath: string, sshkey: string
     
                  // default: either local or no default (i.e., this is required)
                  // "local" is probably something we only want certain users to
                  // be able to do, since the user would have to know how/where to
                  // retrieve the data.
        '''
        warnings = []
        stype = ''
    
        for skey in xdict.keys():
            if skey.lower() == 'storagetype':
                stype = xdict[skey]
                if stype.lower() not in ['local', 's3', 'ssh']:
                    warnings.append('Storage type ' + str(stype) + ' unrecognized.')
                else:
                    stype = exptstate.setConfig('storage', stype.lower())
            elif skey.lower() == 'storageparams':
                sparam = xdict['storageparams']
                for k in sparam.keys():
                    if k == 's3key':
                        exptstate.setConfig('s3key', sparam[k])
                    elif k == 's3bucket':
                        exptstate.setConfig('s3bucket', sparam[k])
                    elif k == 's3secret':
                        exptstate.setConfig('s3secret', sparam[k])
                    elif k == 'sshuser':
                        exptstate.setConfig('sshuser', sparam[k])
                    elif k == 'sshhost':
                        exptstate.setConfig('sshhost', sparam[k])
                    elif k == 'sshport':
                        exptstate.setConfig('sshport', sparam[k])
                    elif k == 'sshpath':
                        exptstate.setConfig('sshpath', sparam[k])
                    elif k == 'sshkey':
                        exptstate.setConfig('sshkey', sparam[k])
                    elif k == 'local_storage_dir':
                        exptstate.setConfig('localdir', sparam[k])
                    elif k == 'rollover_interval':
                        rollint = sparam[k]
                        try:
                            rollint = int(rollint)
                        except:
                            rollint = 1
                        exptstate.setConfig('rollover', rollint)
                    else:
                        warnings.append('Unrecognized storage param: ' + str(k))
        return warnings
    
    
    def doMetaDataConfig(self, exptstate, xdict):
        '''
        MetaDataSpec (struct)
           UserText (string)     // user-defined description to attach with the
                                 // data so that he/she has their own note as to
                                 // what went into the experiment
                                 // default: no user metadata
     
        '''
        warnings = []
        for mdkey in xdict.keys():
            if mdkey.lower() == 'usertext':
                exptstate.setConfig('metatext', xdict[mdkey])
            else:
                warnings.append('Unrecognized metadata param ' + str(mdkey))
        return warnings
    
    
    def doCaptureConfig(self, exptstate, xdict):
        '''
        CaptureSpec (struct)
           filterexpr (string)   // e.g., pcap expression
           device (string)       // specific physical device name
                                 // default: default device and no filter expression
        '''
        warnings = []
        for key in xdict.keys():
            self.logger.debug('captureconfig key %s -> %s' % (key, xdict[key]))
            if key.lower() == 'filterexpr':
                exptstate.setConfig('filterexpr', xdict[key])
            elif key.lower()  == 'device':
                exptstate.setConfig('device', xdict[key])
            else:
                warnings.append('Unrecognized capture param ' + str(key))
        return warnings
    
    
    def doTransformConfig(self, exptstate, xdict):
        '''
        TransformSpec (struct)   
           SampleSpec (struct)
               sampletype (string) "everyN", or "uniformrandom"
               sampleparams (array of strings?)
                  // types: "everyN", "uniformrandom", 
                  // for these two sample types, there's only one parameter
                  // necessary, but other sample types (e.g., trajectory sampling)
                  // might have more than one parameter necessary.  to pass those
                  // parameters we might either have an array of strings, or perhaps
                  // better, we could have named elements in the SampleSpec structure
                  // for each necessary parameter.  e.g., "N" (if "everyN" is the type),
                  // or "p" if the type is "uniformrandom"
     
                  // default: no transformation
     
           AnonSpec (struct)
               anontype (string) 'anonymize'
               anonkey (string) 
     
           AggregationSpec (struct)
               aggtype (string)  'combine_pkts_flows', 'combine_pkts'
               aggparams (array of strings?)
                  // no need to define these yet, but for aggregation into 
                  // flow records, we might have parameters to define specifically
                  // what constitutes a flow (e.g., 5-tuple or some other combo)
     
                  // default: no aggregation
        '''
        warnings = []
        for key in xdict.keys():
            self.logger.debug('Transform spec key %s -> %s' % (key, str(xdict[key])))
            if key.lower() == 'samplespec':
                sampdict = xdict[key]
                for skey in sampdict.keys():
                    self.logger.debug('samplespec key %s -> %s' % (skey, str(sampdict[skey])))
                    if skey.lower() == 'sampletype':
                        stype = sampdict[skey]
                        if stype.lower() in ['everyn', 'uniformrandom', 'none']:
                            exptstate.setConfig('sampletype', sampdict[skey])
                        else:
                            warnings.append('Unrecognized sample type ' + str(skey))
                    elif skey.lower() == 'sampleparams':
                        sparams = sampdict[skey]
                        for spkey in sparams.keys():
                            if spkey.lower() == 'n' or spkey.lower() == 'p':
                                sparm = -1.0
                                try:
                                    sparm = float(sparams[spkey])
                                except:
                                    pass
                                if sparm < 0:
                                    warnings.append('Invalid sample parameter ' + str(sparams[spkey]))
                                else:
                                    exptstate.setConfig('sampleparam', sparm)
                    else:
                        warnings.append('Unrecognized sample parameter ' + str(skey))
                    
            elif key.lower() == 'anonspec':
                anondict = xdict[key]
                for akey in anondict.keys():
                    if akey.lower() == 'anontype':
                        exptstate.setConfig('anontype', anondict[akey])
                    elif akey.lower() == 'anonkey':
                        exptstate.setConfig('anonkey',anondict[akey])
                    else:
                        warnings.append('Unrecognized anonymization parameter ' + str(akey))
    
            elif key.lower() == 'aggregationspec':
                aggdict = xdict[key]
                for akey in aggdict.keys():
                    if akey.lower() == 'aggtype':
                        exptstate.setConfig('aggregationtype', aggdict[akey])
                    else:
                        warnings.append('Unrecognized aggregation parameter ' + str(akey))
            else:
                warnings.append('Unrecognized transformation type ' + str(key))
    
        return warnings
    

    def doConfig(self, exptstate, cdict):
        '''
        input: dictionary with configuration sections:
        - VLAN
        - MetaDataSpec
        - CaptureSpec
        - TransformSpec
        - StorageSpec
        (may want a CompressionSpec eventually)
        return list of warning strings
        '''
        warnings = []
    
        for key in cdict.keys():
            self.logger.debug('Configure key %s -> %s' % (key, str(cdict[key])))
            
            if key.lower() == 'vlan':
                vlan = -1
                try:
                    vlan = int(cdict[key])
                except:
                    pass
                exptstate.setConfig('vlan', vlan)
            elif key.lower() == 'metadataspec':
                warnings += self.doMetaDataConfig(exptstate, cdict[key])
            elif key.lower() == 'capturespec':
                warnings += self.doCaptureConfig(exptstate, cdict[key])
            elif key.lower() == 'transformspec':
                warnings += self.doTransformConfig(exptstate, cdict[key])
            elif key.lower() == 'anonspec':
                warnings += self.doTransformConfig(exptstate, {'AnonSpec':cdict[key]})
            elif key.lower() == 'aggregationspec':
                warnings += self.doTransformConfig(exptstate, {'AggregationSpec':cdict[key]})
            elif key.lower() == 'storagespec':
                warnings += self.doStorageConfig(exptstate, cdict[key])
            elif key.lower() == 'experimentid':
                pass
            elif key.lower() == 'methodname':
                pass
            elif key.lower() == 'sitelocation':
                exptstate.setConfig('sitelocation', cdict[key].upper())
            elif key.lower() == 'devicename':
                exptstate.setConfig('devicehost', cdict[key])
            elif key.lower() == 'configname':
                exptstate.setConfig('configname', cdict[key])
            else:
                warnings.append('Unrecognized configuration section ' + str(key))
        self.logger.debug('Exiting configuration routine.')
        return warnings


def proxy_main(port, host, debug, basedir, defaultdevice, capdexec):
    '''
    This method starts the proxy manager by starting to register the various functions in the XMLRPCServer
    and spawning multiple child processes for the various Experiments as well as starting the Storage Agent.
    
    port -- Port to be used for communication with the XMLRPC Server 
    host -- The address of the host to provide support for the XMLRPC Server
    basedir -- Directory to which .metadata and .pcap files for an experiment will be exported.
    defaultdevice -- Ethernet device in current node to be used for listening and communication
    capdexec -- Capturing Device to be used.
    '''
    fileout = logging.FileHandler('capd_proxy.log') 
    format = logging.Formatter('%(asctime)s %(name)-14s %(levelname)-8s %(message)s')
    fileout.setFormatter(format)   
    logger = logging.getLogger('capd_proxy')
    logger.addHandler(fileout)

    if debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    logger.info('capd_proxy starting up.')

    # actives = ActiveExperiments()
    # handler = ExperimentManager(actives, logger, debug, basedir, capdexec)
    handler = ExperimentManager(logger, debug, basedir, 
                                defaultdevice, capdexec)

    server = SimpleXMLRPCServer((host, port), requestHandler=RequestHandler)
    server.register_introspection_functions()

    server.register_function(handler.startExperiment)
    server.register_function(handler.StartExperiment)
    server.register_function(handler.stopExperiment)
    server.register_function(handler.StopExperiment)
    server.register_function(handler.configureExperiment)
    server.register_function(handler.ConfigureExperiment)
    server.register_function(handler.getExperimentStats)
    server.register_function(handler.GetExperimentStats)
    server.register_function(handler.GetStorageLog)
    server.register_function(handler.getStorageLog)
    server.register_function(handler.pauseExperiment)
    server.register_function(handler.PauseExperiment)
    server.register_function(handler.resumeExperiment)
    server.register_function(handler.ResumeExperiment)
    server.register_function(handler.testExperimentStorage)
    server.register_function(handler.TestExperimentStorage)
    server.register_function(handler.getState)

    server.timeout = 1.0

    global running
    while running:
        try:
            # server.serve_forever()
            server.handle_request()
            handler.reapChildren()
        except Exception,e:
            logger.debug('Caught exception while serving XML/RPC requests: '+str(e)) 
    logger.debug("proxy out of main loop")

    handler.stopStorageAgents()

    nchildren = 0
    try:
        nchildren = len(multiprocessing.active_children())
    except OSError,e:
        if 'No child process' in e:
            nchildren = 0

    logger.debug('Active children remaining: %d' % (nchildren))
    while nchildren > 0:
        try:
            for p in multiprocessing.active_children():
                p.terminate()
                p.join(1)
        except OSError,e:
            if 'No child process' in e:
                nchildren = 0
    logger.info('No more child processes alive --- going down.')


if __name__ == '__main__':
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
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(name)-14s %(levelname)-8s %(message)s', filename='capd_proxy.log')
    else:
        logging.basicConfig(level=logging.INFO, format='%(asctime)s %(name)-14s %(levelname)-8s %(message)s', filename='capd_proxy.log')
      
    console = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s %(name)-14s %(levelname)-8s %(message)s')
    console.setFormatter(formatter)
    logging.getLogger('').addHandler(console)
    
    logger = logging.getLogger('capd_proxy')
    
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(name)-14s %(levelname)-8s %(message)s')   

    proxy_main(options.port, options.host, options.debug, options.basedir, options.defaultdevice, options.capdexec)

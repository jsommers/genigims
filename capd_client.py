#!/usr/bin/env python

__author__ = 'jsommers@colgate.edu'
__doc__ = '''
capd_client.py is a simple driver to test the XML/RPC proxy that
interacts with the GIMS GUI.  (That is, this program masquerades as
the GIMS GUI for testing.)

This source code is licensed under the GENI public license.
See www.geni.net, or "geni_public_license.txt" that should 
have accompanied this software.
'''

import xmlrpclib
import os
import sys
import time


def methodtest(rpchandle):
    '''
    Won't actually do anything unless test experiment has previously been
    configured.
    '''
    print rpchandle.startExperiment({'ExperimentId':'test'})
    print rpchandle.stopExperiment({'ExperimentId':'test'})
    print rpchandle.getExperimentStats({'ExperimentId':'test'})
    print rpchandle.getStorageLog({'ExperimentId':'test'},5)



def configtest(rpchandle, accesskey, secretkey, bucket):
    '''
    Overall configuration method that defines the parameters to be used in an experiment.
    Configures all three types of storage information.
    '''
    cdict = {'ExperimentId':'test' }
    print rpchandle.configureExperiment(cdict)
    print rpchandle.getExperimentStats({'ExperimentId':'test'})
    print rpchandle.getStorageLog({'ExperimentId':'test'},5)

    capdict = {'filterexpr':'ip', 'device':'dag0'}

    # use *all* storage params as GIMS web page does
    storedict = {'storagetype':'local'}
    storedict = {'storagetype':'s3', 'storageparams':{'s3accesskey': accesskey, 's3secretkey': secretkey, 's3bucket': bucket}}
    
    # slurp in my private ssh key
    fin = open('/Users/jsommers/.ssh/id_rsa')
    xkey = fin.read()
    fin.close()
    storedict = {'storagetype':'ssh', 'storageparams':{'sshhost':'10.0.1.3', 'sshuser':'sommers', 'sshkey':xkey}}

    transformdict = {'AnonSpec':{}, 'SampleSpec':{}, 'AggregationSpec':{}}
    metadict = {'usertext':'this is some user metadata text'}

    cdict = {'ExperimentId':'test', 'CaptureSpec':{'filterexpr':'ip', 'device':'en1'} }
    print rpchandle.configureExperiment(cdict)
    print rpchandle.getExperimentStats({'ExperimentId':'test'})
    print rpchandle.getStorageLog({'ExperimentId':'test'},5)

    cdict = {'ExperimentId':'test', 'StorageSpec':storedict, 'TransformSpec':transformdict, 'MetaDataSpec':metadict}
    print rpchandle.configureExperiment(cdict)
    print rpchandle.getExperimentStats({'ExperimentId':'test'})



def configexptlocal(rpchandle):
    '''
    Overall configuration method that defines the parameters to be used in an experiment.
    Unlike configtest it only configures the experiment to use local storage.
    '''
    cdict = {'ExperimentId':'test' }
    print rpchandle.configureExperiment(cdict)
    print rpchandle.getExperimentStats({'ExperimentId':'test'})
    print rpchandle.getStorageLog({'ExperimentId':'test'},5)
    
    capdict = {'filterexpr':'ip', 'device':'dag0'}
    storedict = {'storagetype':'local'}
    transformdict = {'AnonSpec':{}, 'SampleSpec':{}, 'AggregationSpec':{}}
    metadict = {'usertext':'this is some user metadata text'}

    cdict = {'ExperimentId':'test', 'CaptureSpec':{'filterexpr':'ip', 'device':'en1'} }
    print rpchandle.configureExperiment(cdict)
    print rpchandle.getExperimentStats({'ExperimentId':'test'})
    print rpchandle.getStorageLog({'ExperimentId':'test'},5)

    cdict = {'ExperimentId':'test', 'StorageSpec':storedict}
    print rpchandle.configureExperiment(cdict)
    print rpchandle.getExperimentStats({'ExperimentId':'test'})
    print rpchandle.getStorageLog({'ExperimentId':'test'},5)


def configexpts3(rpchandle, accesskey, secretkey, bucket):
    '''
    Overall configuration method that defines the parameters to be used in an experiment.
    Unlike configtest it only configures the experiment to use Amazon's s3 storage.
    '''
    cdict = {'ExperimentId':'test' }
    print rpchandle.configureExperiment(cdict)
    print rpchandle.getExperimentStats({'ExperimentId':'test'})
    capdict = {'filterexpr':'ip', 'device':'dag0'}
    storedict = {'storagetype':'s3', 'storageparams':{'s3accesskey': accesskey, 's3secretkey': secretkey, 's3bucket': bucket}}
    transformdict = {'AnonSpec':{}, 'SampleSpec':{}, 'AggregationSpec':{}}
    metadict = {'usertext':'this is some user metadata text'}

    cdict = {'ExperimentId':'test', 'CaptureSpec':{'filterexpr':'ip', 'device':'en1'} }
    print rpchandle.configureExperiment(cdict)
    print rpchandle.getExperimentStats({'ExperimentId':'test'})

    cdict = {'ExperimentId':'test', 'StorageSpec':storedict, 'TransformSpec':transformdict}
    print rpchandle.configureExperiment(cdict)
    print rpchandle.getExperimentStats({'ExperimentId':'test'})


def configexptssh(rpchandle):
    '''
    Overall configuration method that defines the parameters to be used in an experiment.
    Unlike configtest it only configures the experiment to use ssh storage.
    '''
    cdict = {'ExperimentId':'test' }
    print rpchandle.configureExperiment(cdict)
    print rpchandle.getExperimentStats({'ExperimentId':'test'})
    capdict = {'filterexpr':'ip', 'device':'dag0'}

    # slurp in my private ssh key
    fin = open('/Users/jsommers/.ssh/id_rsa')
    xkey = fin.read()
    fin.close()
    storedict = {'storagetype':'ssh', 'storageparams':{'sshhost':'10.0.1.3', 'sshuser':'sommers', 'sshkey':xkey}}

    transformdict = {'AnonSpec':{}, 'SampleSpec':{}, 'AggregationSpec':{}}
    metadict = {'usertext':'this is some user metadata text'}

    cdict = {'ExperimentId':'test', 'CaptureSpec':{'filterexpr':'ip', 'device':'en1'} }
    print rpchandle.configureExperiment(cdict)
    print rpchandle.getExperimentStats({'ExperimentId':'test'})

    cdict = {'ExperimentId':'test', 'StorageSpec':storedict}
    print rpchandle.configureExperiment(cdict)
    print rpchandle.getExperimentStats({'ExperimentId':'test'})

def startexpt(rpchandle):
    '''
    RPC call to startExperiment method.
    '''
    print rpchandle.startExperiment({'ExperimentId':'test'})

def pauseexpt(rpchandle):
    '''
    RPC call to pauseexpt method.
    '''
    print rpchandle.pauseExperiment({'ExperimentId':'test'})

def resumeexpt(rpchandle):
    '''
    RPC call to resumeexpt method.
    '''
    print rpchandle.resumeExperiment({'ExperimentId':'test'})

def stopexpt(rpchandle):
    '''
    RPC call to stopexpt method.
    '''
    print rpchandle.stopExperiment({'ExperimentId':'test'})

def getstoragelog(rpchandle):
    '''
    RPC call to getStorageLog method.
    '''
    print rpchandle.getStorageLog({'ExperimentId':'test'}, 5)

def getexptstate(rpchandle):
    '''
    RPC call to getExperimentState method.
    '''
    print rpchandle.getExperimentStats({'ExperimentId':'test'})
    print rpchandle.getState()


def teststorage(rpchandle):
    '''
    Requires that experiment storage has previously been configured.
    RPC call to testExperimentStorage.
    '''
    print rpchandle.testExperimentStorage({'ExperimentId':'test'})


def runtest(rpchandle, testlist):
    '''
    Executes a list of methods on a particular experiment.
    '''
    for test in testlist:
        try:
            test(rpchandle)
        except Exception,e:
            print 'Exception while running test:',str(e)


def xpause(rpchandle):
    '''
    Pauses the current capd_client to allow the experiment to 
    '''
    print "Sleeping 45 seconds."
    time.sleep(45)



def main():
    '''
    This method starts the XMLRPC Server, configures an experiment and executes list of given methods on the given experiments.
    '''
    # add verbose=True to c'tor to turn on lots of xml/rpc chatter
    # rpchandle = xmlrpclib.ServerProxy("http://netlab.colgate.edu:8001/", use_datetime=True)
    rpchandle = xmlrpclib.ServerProxy("http://localhost:8001/", use_datetime=True)

    #mlist = rpchandle.system.listMethods()
    #print "list methods",mlist

    # configure, start experiment, wait, then stop experiment
    # testlist = [ configexptlocal, configexptssh, getexptstate, startexpt, stopexpt, getexptstate ]
    # testlist = [ configexptlocal, configexptssh, getexptstate ]
    # testlist = [ configexpts3, getexptstate, startexpt, stopexpt, getexptstate ]

    # testlist = [ configexptlocal, startexpt, xpause, getexptstate, pauseexpt, xpause, resumeexpt, xpause, getexptstate, xpause, stopexpt, getexptstate ]
    testlist = [ configexptlocal, startexpt, xpause, getexptstate,getstoragelog, stopexpt, getstoragelog ]
    #testlist = [ configexptlocal, startexpt, xpause, getexptstate, xpause, getexptstate, xpause, getexptstate, xpause, getexptstate, xpause, getexptstate, stopexpt, getexptstate ]     
    runtest(rpchandle, testlist)

    # configure and test storage
    # testlist = [ configexptssh, getexptstate, teststorage ]
    # testlist = [ configexpts3, getexptstate, teststorage ]
    # runtest(rpchandle, testlist)

    # configure expt and get state
    # testlist = [ configexptssh, getexptstate ]
    # runtest(rpchandle, testlist)

    # just get all state from proxy daemon
    # testlist = [ getexptstate ]
    # runtest(rpchandle, testlist)


if __name__ == '__main__':
    main()

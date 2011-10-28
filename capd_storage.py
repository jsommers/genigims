#!/usr/bin/env python

__author__ = 'jsommers@colgate.edu'
__doc__ = '''
Storage upload functions for capture daemon proxy server that handles 
calls from GIMS UI-side client.

This source code is licensed under the GENI public license.
See www.geni.net, or "geni_public_license.txt" that should
have accompanied this software.
'''

import os
import sys
import threading
import logging
import multiprocessing
import Queue
import signal
import xml.etree.ElementTree
import time
import StringIO

running = True

def sighandler(signum, stackframe):
    global running
    running = False


try:
    import paramiko
    have_ssh = True
except:
    have_ssh = False

try:
    import boto.s3 as s3
    have_s3 = True
except:
    have_s3 = False


def mark_complete_upload(basedir, expt, storetype, metaname, logger):
    '''
    Includes into the completed_upload file entry for the uploaded file 
    and records the new number of uploaded files for getExperimentStats
    ''' 
    completed_upload = './' + os.sep + 'completed_upload.txt'
 
    try:
        fd = os.open(completed_upload, os.O_WRONLY|os.O_APPEND|os.O_CREAT)
        xstr = '%s %s %s %s\n' % (expt,os.path.basename(metaname),storetype,time.strftime("%Y%m%d-%H%M%S",time.gmtime())) 
        os.write(fd,xstr)
        os.close(fd)
        logger.info('%s Uploaded file %s. Storage type is %s.' % (expt, metaname, storetype))        
    except OSError,e:
        print >>sys.stderr,'Unable to write to completed_upload.txt file:',str(e)
       

def local_upload(basedir, log, exptid, filelist):
    '''
    Local upload handler.  Basically does a whole lot of nothing.
    '''
    for ftup in filelist:
        log.info('%s Local file %s for experiment is ready.' % (exptid, ftup[0]))
        mark_complete_upload(basedir, exptid, 'local', ftup[0], log)


def s3_upload(basedir, log, exptid, s3accesskey, s3secretkey, bucketname, filelist):
    '''
    Amazon S3 upload handler.  Normally spawned in a separate thread to handle
    uploading a list of files to a given bucket, with the given credentials.
    '''
    if not len(filelist): return

    try:
        #log.debug('s3 access key: %s' % (s3accesskey))
        #log.debug('s3 secret key: %s' % (s3secretkey))
        #log.debug('s3 bucket: %s' % (bucketname))
        conn = s3.Connection(aws_access_key_id=s3accesskey, aws_secret_access_key=s3secretkey)
        cid = conn.get_canonical_user_id()
        log.debug('%s Got s3 connection for experiment; canonical s3 user id: %s' % (exptid, cid))

        b = None
        try:
            b = conn.get_bucket(bucketname)
        except:
            pass

        if not b:
            log.warn('%s No such bucket %s exists for experiment --- creating it' % (exptid, bucketname))
            conn.create_bucket(bucketname)

        for ftup in filelist:
            log.info('%s Uploading file %s to s3 bucket %s' % (exptid, str(ftup[0]), bucketname))
            key = b.new_key(ftup[1])
            key.set_contents_from_filename(ftup[0])
            mark_complete_upload(basedir, exptid, 's3', ftup[0], log)
        

    except Exception,e:
        log.warn('%s Upload of file to bucket %s failed: %s' % (exptid, bucketname, str(e)))


def sftp_upload(basedir, log, exptid, hostname, username, pkeystr, filelist, remotepath, port=22):
    '''
    SSH upload handler.  Needs a string containing the private SSH key
    (as well as other relevant SSH info).  Normally spawned in a
    separate thread to upload a list of files to the given remote
    destination.
    '''
    if not len(filelist): return

    log.debug('%s In sftp_upload; uploading to %s@%s' % (exptid, username, hostname))
    for f in filelist:
        log.debug('%s Going to move %s -> %s' % (exptid, f[0], f[1]))

    try:
        fobj = StringIO.StringIO(pkeystr)
        privkey = paramiko.RSAKey.from_private_key(fobj)
        fobj.close()
        t = paramiko.Transport((hostname, port))
        t.use_compression(True) 
        t.connect(username=username, pkey=privkey)
        sftp = paramiko.SFTPClient.from_transport(t)
    except paramiko.SSHException,e:
        log.warn(exptid + ' Error connecting to remote SSH server: ' + str(e))
        return

    remotepath = remotepath+os.sep+exptid

    try:
        sftp.mkdir(remotepath)
    except:
        # essentially ignore errors; really fail if we can't chdir
        pass

    try:
        sftp.chdir(remotepath)
    except Exception,e:
        log.warn(exptid + ' Error chdiring to destination folder on SSH server: ' + str(e))
        return

    for ftup in filelist:
        log.info(exptid + ' Starting upload of file '+str(ftup[0])+' to '+username+'@'+hostname+':'+str(ftup[1]))
        try:
            sftp.put(ftup[0], ftup[1])
            log.info(exptid + ' Finished upload of file '+str(ftup[0])+' to '+username+'@'+hostname+':'+str(ftup[1]))
        except Exception,e:
            log.warn(exptid + ' Error transferring file over sftp: ' + str(e))

        mark_complete_upload(basedir, exptid, 'ssh', ftup[0], log)

    try:
        t.close()
    except paramiko.SSHException,e:
        log.warn(exptid + ' Error connecting to remote SSH server: ' + str(e))
    

def update_metadata(filelist):
    '''
    Update file metadata prior to upload.   ** FIXME **
    '''
    # print filelist
    pass


def uploader_entry(logger, exptid, basedir, metadir, metafile, storetype, storecred):
    '''
    Thread entrypoint for performing upload of a metadata file and
    data file.
    '''
    filelist = [ metafile ]
    etree = xml.etree.ElementTree.parse(metadir + os.sep + filelist[0])
    datael = etree.find('data_file')
    if datael != None:
        filelist.append(datael.text[:].strip())

    # full-path list of source files to transfer
    srcflist = [ metadir + os.sep + f for f in filelist ]

    # perform updates to metadata
    update_metadata(srcflist)

    if storetype == 's3':
        s3_upload(basedir, logger, exptid, storecred[0], storecred[1], storecred[2], zip(srcflist, filelist))

    elif storetype == 'ssh':
        # basenames = filelist[:]
        remotepath = storecred[3] + os.sep
        # destflist = [ xpath + f for f in basenames ]
        sftp_upload(basedir, logger, exptid, storecred[1], storecred[0], storecred[2], zip(srcflist, filelist), remotepath, storecred[4])

    else: # local storage
        local_upload(basedir, logger, exptid, zip(srcflist, filelist))



def storage_agent(recvq, sendq, basedir, debug):
    '''
    Main process entrypoint for a storage agent.  One storage agent is
    started up per capture proxy daemon process and handles all available
    types of uploading capabilities (local, s3, ssh).
    '''
    
    fileout = logging.FileHandler('storage_agent.log')
    format = logging.Formatter('%(asctime)s %(name)-14s %(levelname)-8s %(message)s')
    fileout.setFormatter(format)
    logger = logging.getLogger('storage_agent')    
    logger.addHandler(fileout)

    if debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
    logger.info("GEN Storage agent starting up.")
    logger.info("GEN Using local storage.")

    if have_s3:
        logger.info("GEN Using s3 storage.")
    else:
        logger.info("GEN No s3 storage capability.")

    if have_ssh:
        logger.info("GEN Using ssh storage.")
        try:
            # underlying crypto library requires that rng is reseeded post-fork
            # ugh.  need to unconditionally handle any exceptions; different
            # versions of the library behave differently.
            import Crypto.Random
            Crypto.Random.atfork()
        except:
            pass
    else:
        logger.info("GEN No ssh storage capability.")

    signal.signal(signal.SIGINT, sighandler)
    signal.signal(signal.SIGTERM, sighandler)

    recvq.cancel_join_thread()
    sendq.cancel_join_thread()

    experiments = {}
    moverthreads = {}
    experimentstoremove = []
    completed_capture = './' + os.sep + 'completed_capture.txt'
    completed_upload = './' + os.sep + 'completed_upload.txt'

    # read in file that contains list of meta files that have been
    # handled for upload already.  use this list to determine whether
    # a given file needs to be uploaded or not.
    try:
        upload_inf = open(completed_upload)
        for line in upload_inf:
            (expt,metafile,stype,ts) = line.strip().split()
            if expt in experiments:
                expt_info = experiments[expt]
            else:
                expt_info = [ 'Unknown', 'Unknown', set() ]
                experiments[expt] = expt_info
            expt_info[-1].add(metafile)
        upload_inf.close()
    except Exception,e:
        logger.info("GEN completed_upload.txt didn't previously exist.")
        
    global running
    while running or len(moverthreads):
        task = None
        try:
            task = recvq.get(True, 5.0)
        except Queue.Empty:
            pass
        except IOError,e:
            logger.info('GEN IO exception while waiting for queue receive: %s' % (str(e)))
            continue

        # test whether we should exit; we've been asked to exit, but can't
        # until no more upload threads remain.
        if not running and len(moverthreads):
         #put id here
            logger.info("GEN Storage task waiting to die --- waiting for %d upload thread to complete" % (len(moverthreads)))

        # go through list of experiments to remove; test whether there
        # are any remaining upload threads left.  if not, remove the
        # experiment 
        for expt in experimentstoremove:
            count = len([ t for t in moverthreads if moverthreads[t] == expt ])
            if count == 0:
                # no more upload threads, and experiments was stopped, so
                # remove it.
                del experiments[expt]
                logger.info("%s Experiment removed; no more upload threads remain." % (expt))

        if task:
            # we'll get one of three commands: STOP, NEWEXPT, or RMEXPT
            if task[0] == 'STOP':
                # time for the storage process to die
                logger.info("GEN Received STOP command.")
                running = False
                if len(moverthreads):
                    logger.info("GEN Waiting for %d upload thread to complete" % (len(moverthreads)))

            elif task[0] == 'NEWEXPT':
                # a new experiment has started; organize the experiment
                # info and register the directory to be periodically
                # checked to upload contents
                expt = task[1]
                storetype = task[2]
                storecred = task[3]
                exptdir = task[4]
                if expt in experiments:
                    # if experiment already exists, just update storage info
                    experiments[expt][0] = storetype
                    experiments[expt][1] = storecred
                else:
                    experiments[expt] = [ storetype, storecred, set()]
                logger.info("%s new experiment of interest registered." % (expt))
            elif task[0] == 'RMEXPT':
                # an experiment has stopped.  don't remove this experiment
                # from interest until any uploads have completed.  for now,
                # don't bother removing any local files.
                expt = task[1]
                logger.info("%s Experiment marked for removal." % (expt))
                experimentstoremove.append(expt)

        # test whether any mover threads are done; clean them up if
        # possible.
        deadmovers = []
        for t in moverthreads:
            if not t.isAlive():
                t.join(timeout=1)
                deadmovers.append(t)

        for t in deadmovers:
            del moverthreads[t]

        # go through "completed_capture.txt" file that contains
        # a list of all metadata files that are completely done with
        # capture and are awaiting upload
        try: 
            completed_inf = open(completed_capture)
            for line in completed_inf:
                (expname, metafullfile) = line.strip().split()
                metadir = os.path.dirname(metafullfile)
                metafile = os.path.basename(metafullfile)

                if expname not in experiments:
                    experiments[expname] = ['Unknown']
                    logger.info("%s Metadump produced by unknown experiment" % (expname))
                    continue

                # get experiment info for this experiment: storage type,
                # storage credentials, and set of files already transferred
                expt_info = experiments[expname]
                if expt_info[0] == 'Unknown':
                    logger.debug("%s Ignoring experiment with unknown storage details" % (expname))
                    continue
 
                # if this file has already been uploaded, ignore it.
                if metafile in expt_info[-1]:
                    logger.debug("%s File %s for experiment has already been uploaded." % (expname, metafile))
                    continue

                else:
                    # handle upload for this new file.  add it to set
                    # of metafiles that have been "handled", and do
                    # the upload.
                    expt_info[2].add(metafile) 
                    t = threading.Thread(target=uploader_entry, args=(logger, expname, basedir, metadir, metafile, storetype, storecred))
                    moverthreads[t] = expname
                    t.start()
                    logger.debug('GEN Spawned upload thread %s' % (t.getName()))
            completed_inf.close()

        except OSError,e:
            logger.info("GEN exception while probing completed_capture.txt: " + str(e))
        except IOError,e:
            logger.debug("GEN completed_capture.txt doesn't exist.  Nothing to transfer.")

    logger.info("GEN Storage agent terminated.")
    return 0

    
if __name__ == '__main__':
    '''
    Unit tests for storage capabilities.  Simple method for noting local files,
    and uploading to ssh or s3.
    '''
    xkey = '''
'''
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
    toc,fromc = multiprocessing.Queue(),multiprocessing.Queue()
    basedir = os.getcwd() + os.sep + 'capture-daemon'
    # local
    # toc.put( ('NEWEXPT', 'unnamed', 'local', os.getcwd(), os.getcwd()) )
    # ssh
    # toc.put( ('NEWEXPT', 'EXP_A4605CED', 'ssh', ('jsommers','cs.colgate.edu',xkey,'','22'), os.getcwd()))
    # s3
    # toc.put( ('NEWEXPT', 'EXP_A4605CED', 's3', ('access','secret','sommers.joel.buckettest'), os.getcwd()))

    storage_agent(toc, fromc, basedir, 1)

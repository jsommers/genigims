/*
 * capture-daemon.c; part of the GIMS GENI project.
 * 
 * This source code is licensed under the GENI public license.
 * See www.geni.net, or "geni_public_license.txt" that should 
 * have accompanied this software.
 */
#include "config.h"
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <signal.h>
#include <sys/file.h>
#include <fcntl.h>
#include <netinet/ip.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>



#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef TIME_WITH_SYS_TIME
#include <sys/time.h>
#include <time.h>
#else
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#else
#include <time.h>
#endif
#endif

#ifdef HAVE_PCAP_PCAP_H
#include <pcap/pcap.h>
#else
#ifdef HAVE_PCAP_H
#include <pcap.h>
#endif
#endif
#include "flowagg.h"
#ifdef ANONYMIZE
#include "anonymize.h"
#endif


#define SIZE_ETHERNET 14
#define AGG_COUNT "count"
#define AGG_FLOW  "flow"
#define MAXOUTNAME 256
#define SAMPLE_ALL 1
#define SAMPLE_PROBABILITY 2
#define SAMPLE_TIME_INTERVAL 3
#define DONE_FILE "completed_capture.txt"
#define NUMINTS (50)
#define FILESIZE (NUMINTS * sizeof(int))



/**
 * Updates a file containing a list of the completed files containing experiment
 * metadata and pcap traces.
 *
 * @param expt_name Experiment Name
 * @param done_filename Filename to write to.
 * @return Void
 */
void update_completed_files(const char *expt_name, const char *done_filename)
{
    int fd = open(DONE_FILE, O_CREAT|O_WRONLY|O_APPEND, 0664);
    if (fd < 0)
    {
        fprintf(stderr, "error opening completed file: %d/%s\n", errno, strerror(errno));
        return;
    }
    char buf[1024];
    snprintf(buf, 1024, "%s %s\n", expt_name, done_filename);
    int wrote = write(fd, buf, strlen(buf));
    if (wrote < 0)
    {
        fprintf(stderr, "error writing to completed file: %d/%s\n", errno, strerror(errno));
    }
    close(fd);
}

/**
 * Writes stats do the metadata file for the corresponding experiment.
 *
 * @param metadata_fh Metadata file to be written corresponding to the experiment
 * @param pcap_handle Packet Capture handler to be used.
 * @param current_time Current system time use for the time stamp.
 * @param packet_count Number of packets captured.
 * @param byte_count Number of bytes captured.
 * @return Void
 */
void do_capture_stats(FILE *metadata_fh, pcap_t *pcap_handle, time_t current_time, uint64_t packet_count, uint64_t byte_count)
{
    struct pcap_stat stats;
    pcap_stats(pcap_handle, &stats);
    
    if (metadata_fh)
    {
        struct tm *tms = gmtime(&current_time);
        fprintf(metadata_fh, "\t<stat_update timestamp=\"%02d:%02d:%02d\">\n", tms->tm_hour, tms->tm_min, tms->tm_sec);
        fprintf(metadata_fh, "\t\t<device_packets_received>%u</device_packets_received>\n", stats.ps_recv);
        fprintf(metadata_fh, "\t\t<device_packets_dropped>%u</device_packets_dropped>\n", stats.ps_drop);
        fprintf(metadata_fh, "\t\t<device_interface_drops>%u</device_interface_drops>\n", stats.ps_ifdrop);
        fprintf(metadata_fh, "\t\t<packets_observed>%llu</packets_observed>\n", packet_count);
        fprintf(metadata_fh, "\t\t<bytes_observed>%llu</bytes_observed>\n", byte_count);
        fprintf(metadata_fh, "\t</stat_update>\n");
    }
}

/**
 * Writes the header information to the metadata file for the corresponding experiment.
 *
 * @param fh Metadata file to be written corresponding to the experiment
 * @param now Current system time use for the time stamp.
 * @param datafile PCAP file to be referenced.
 * @param count_agg If 1 or > aggreggation was used. 0 < aggregation was not used.
 * @param user_metadata String contained information about the user.
 * @param gims_location Location of the Node that captured particular traffic.
 * @param sample_type Type of sample use for sampling packet traffic.
 * @param sample_rate Rate at which samples should be taken.
 * @param exp_name Experiment Name.
 * @param rollover_interval After how long should a new set of metadata & pcap files be generated.
 * @param aggstr Determines if aggregation is being performed.
 * @param anon_key Anonymization key to be used.
 * @return Void
 */
void do_metadata_header(FILE *fh, time_t now, const char *datafile, int count_agg,
                        const char *user_metadata, const char *gims_location,
                        int sample_type, double sample_rate, const char *exp_name,
                        const char *dev, const char *filter,
                        int rollover_interval, const char *aggstr,
                        const char *anon_key)
{
    struct tm *tms = gmtime(&now);
    fprintf(fh, "<?xml version=\"1.0\"?>\n");
    fprintf(fh, "<gims_metadata>\n");
    if(!count_agg)
    {
        fprintf(fh, "\t<data_file>%s</data_file>\n", datafile);

#if HAVE_YAF
        if (aggstr && !strcmp(aggstr,AGG_FLOW))
            fprintf(fh,"\t<data_type>yaf</data_type>\n");
        else
#endif
            fprintf(fh,"\t<data_type>pcap</data_type>\n");
    }
    
    fprintf(fh, "\t<start_time>%04d-%02d-%02d %2d:%02d:%02d</start_time>\n", 1900+tms->tm_year, tms->tm_mon, tms->tm_mday, tms->tm_hour, tms->tm_min, tms->tm_sec);
    fprintf(fh, "\t<creators>\n");
    fprintf(fh, "\t\t<creator>\n");
    fprintf(fh, "\t\t\t<name>FIXME</name>\n");
    fprintf(fh, "\t\t\t<email>someone@fixme.edu</email>\n");
    fprintf(fh, "\t\t</creator>\n");
    fprintf(fh, "\t\t<primary_contact>\n");
    fprintf(fh, "\t\t\t<name>FIXME</name>\n");
    fprintf(fh, "\t\t\t<email>someone@fixme.edu</email>\n");
    fprintf(fh, "\t\t</primary_contact>\n");         
    fprintf(fh, "\t</creators>\n");
    fprintf(fh, "\t<setting>\n");
    fprintf(fh, "\t\t<gims_version>%s</gims_version>\n", GIMS_CAPD_VERSION);
    fprintf(fh, "\t\t<platform>FIXME</platform>\n");
    fprintf(fh, "\t\t<gims_location>%s</gims_location>\n", gims_location);
    fprintf(fh, "\t</setting>\n");
    if (user_metadata)
        fprintf(fh, "\t<user_metadata>%s</user_metadata>\n", user_metadata);
    fprintf(fh, "\t<capture_config>\n");

    if(count_agg) 
    {
        fprintf(fh,"\t\t<aggregation>byte_pkt_count</aggregation>\n");
    }
#if HAVE_YAF
    else if (aggstr && !strcmp(aggstr, AGG_FLOW))
    {
        fprintf(fh,"\t\t<aggregation>ipfix</aggregation>\n");
        fprintf(fh,"\t\t<ipfix_library>" YAF_URL "</ipfix_library>\n");
        fprintf(fh,"\t\t<fixbuf_version>" FIXBUF_VERSION "</fixbuf_version>\n");
        fprintf(fh,"\t\t<yaf_version>" YAF_VERSION "</yaf_version>\n");
    }
#endif
    else
    {
        fprintf(fh,"\t\t<aggregation>none</aggregation>\n");
        fprintf(fh,"\t\t<pcap_version> %d.%d </pcap_version>\n", PCAP_VERSION_MAJOR, PCAP_VERSION_MINOR);
    }

    fprintf(fh, "\t\t<sample_type>%s</sample_type>\n",sample_type==SAMPLE_TIME_INTERVAL?"interval":sample_type==SAMPLE_PROBABILITY?"probability":"all");
    fprintf(fh, "\t\t<sample_rate>%f</sample_rate>\n",sample_rate);
    fprintf(fh, "\t\t<exp_name>%s</exp_name>\n", exp_name);
    fprintf(fh, "\t\t<exp_name>%s</exp_name>\n", exp_name);
    fprintf(fh, "\t\t<device>%s</device>\n\t\t<pcap_filter>%s</pcap_filter>\n",dev,filter);
    fprintf(fh, "\t\t<file_rollover_time>%d</file_rollover_time>\n",rollover_interval);
    fprintf(fh, "\t\t<anonymization>");
    if (NULL != anon_key)
    {
        fprintf(fh, "\n\t\t\t<type>prefix-preserving, addresses only</type>\n");
        fprintf(fh, "\t\t\t<key>0x");
        int i = 0;
        for ( ; i < strlen(anon_key); ++i)
            fprintf(fh, "%c", anon_key[i]);
        fprintf(fh, "</key>\n\t\t");
    }
    else
    {
        fprintf(fh, "none");
    }
    fprintf(fh, "</anonymization>\n");
    fprintf(fh, "\t</capture_config>\n");
}


/**
 * Writes the trailer information to the metadata file for the corresponding experiment.
 *
 * @param metadata_fh Metadata file to be written corresponding to the experiment
 * @param now Current system time use for the time stamp.
 * @param pcount Number of packets captured.
 * @param saved_pcount Number of packets captured plus the previous packet count.
 * @param bcount Number of bytes captured.
 * @param saved_kbytes Number of bytes captured plus the previous byte count.
 * @param aggregation Determines if aggregation is being performed.
 * @return Void: Prints to the metadata file.
 */
void do_metadata_trailer(FILE *metadata_fh, time_t now, uint64_t pcount, uint64_t saved_pcount, uint64_t bcount, double saved_kbytes, int aggregation)
{
    fprintf(metadata_fh, "\t<end_summary>\n");
    struct tm *tms = gmtime(&now);
    fprintf(metadata_fh, "\t\t<end_time>%d:%02d:%02d</end_time>\n", tms->tm_hour, tms->tm_min, tms->tm_sec);                                  
    fprintf(metadata_fh, "\t\t<packets_observed>%llu</packets_observed>\n", pcount);
    if (!aggregation)
        fprintf(metadata_fh, "\t\t<packets_saved>%llu</packets_saved>\n", saved_pcount);
    fprintf(metadata_fh, "\t\t<bytes_observed>%llu</bytes_observed>\n", bcount);
    // fprintf(metadata_fh, "\t\t<byte_count format=\"kilobytes\">%f</byte_count>\n", saved_kbytes);
    fprintf(metadata_fh, "\t</end_summary>\n"); 
    fprintf(metadata_fh, "</gims_metadata>\n");

}


/**
 * Displays the usage information of the configuration parameters for capture daemon.
 *
 * @param progname Name of the program to display the usage for.
 * @return Void: Prints to stderr a list of the possible options for the capture daemon.
 */
void usage(const char *progname)
{
    fprintf(stderr, "usage: %s [options]\n", progname);
    fprintf(stderr, "\t-a for aggregation (count or flow)\n");
    fprintf(stderr, "\t-d for device\n");
    fprintf(stderr, "\t-f for capture from file\n");
    fprintf(stderr, "\t-k for anonymization key (16 unsigned char)\n");
    fprintf(stderr, "\t-l for gims location (e.g., SYR)\n");
    fprintf(stderr, "\t-N for name of the experiment\n");
    fprintf(stderr, "\t-p for output filename prefix (path)\n");
    fprintf(stderr, "\t-r for sample rate (requires -t xx)\n");
    fprintf(stderr, "\t-s for pcap_string\n");
    fprintf(stderr, "\t-t for sample type (3 = rate, 2 = probability)\n");
    fprintf(stderr, "\t-n for start on nth packet (requires -t 3)\n");
    fprintf(stderr, "\t-z for timed rollover interval\n");
    fprintf(stderr, "\t-u for user metadata text\n");
    fprintf(stderr, "\t-h for this message\n");
    exit(0);
}

FILE *make_stats_file(const char *ename)
{
    char tempfname[1024];
    
    snprintf(tempfname, 1024, "stats_%s.txt", ename);
    FILE *temp = fopen(tempfname, "w+");
    if  (temp == NULL) 
    {
	fprintf(stderr, "Couldn't open temporary stats file: %d/%s\n", errno, strerror(errno));
	return NULL;
    }

    return temp;
}


/**
 *global variable to control whether we keep reading in data or not 
 */
int run_capture = 1;

void stop_capture(int signum);


/**
* Main method in capture daemon that manages the whole capture timeline.
* It initaliazes signals, sets up options and capture configurations, 
* starts and continues capturing packets, manages the output file 
* periodically reads capture stats, deals with sampling, anonymization 
* and aggregation.
*/
int main(int argc, char **argv)
{
    /* ********* INITIALIZE SIGNALS ********* */
    if (signal(SIGINT, stop_capture) == SIG_ERR)
    {
        fprintf(stderr, "Cannot initialize signal\n");
        return -1;
    }

    if (signal(SIGTERM, stop_capture) == SIG_ERR)
    {
        fprintf(stderr, "Cannot initialize signal\n");
        return -1;
    }

    /* ********* SET UP OPTIONS ********* */
    char *exp_name = "unnamed";
    char *pcap_string = "ip";
    char *dev = "eth1";
    double sample_rate = 0.0;
    int sample_type = SAMPLE_ALL;
    char *input_file = NULL;
    int start_count = 0;
    char *output_path = "./captured-packets/";
    time_t rollover_interval = 300;
    time_t stats_interval = 30, next_stats = 0;
    char *aggoptstr = NULL;
#define TSLEN 32
    char timestamp[TSLEN];
    int read_from_file = 0;
    int snaplen = 64;
    char *gims_location = "UNK";
    char *user_metadata = NULL;
    char *anon_key = NULL;

#if DEBUG
    fprintf(stderr, "pcap_string: %s\n", pcap_string);
#endif

    int c;
    while (((c = getopt(argc, argv, "a:d:f:hi:k:l:N:n:p:r:s:t:u:z:")) != -1))
    {
        switch (c)
        {
        case 'a':
            aggoptstr = strdup(optarg);
            break;
        case 'p':
            output_path = strdup(optarg);
            break;
        case 'd':
            dev = strdup(optarg);
            break;
        case 'f':
            read_from_file = 1;
            input_file = strdup(optarg);
            break;
        case 'i':
            stats_interval = (time_t)atoi(optarg);
            if (stats_interval <= 0)
                usage(argv[0]);
            break;
	case 'k':
            if (strlen(optarg) == 16)
            {
	        anon_key = strdup(optarg); // straight-up key
            }
            else if (strlen(optarg) == 18)
            {
                anon_key = strdup(optarg+2); // 0xkeystr (hex prefix)
            }
            else
            {
                fprintf(stderr, "Anonymization key isn't long enough.  Ignoring.\n");
            }
	    break;
        case 'l':
            gims_location = strdup(optarg);
            break;
        case 'N':
            exp_name = strdup(optarg);
            break;
        case 'n':
            start_count = atoi(optarg);
            if (start_count < 0)
                usage(argv[0]);
            break;
        case 'r':
            sample_rate = atof(optarg);
            break;
        case 's':
            pcap_string = strdup(optarg);
            break;
        case 't':
            sample_type = atoi(optarg);
            break;
        case 'u':
            user_metadata = strdup(optarg);
            break;
        case 'z':
            rollover_interval = (time_t)atoi(optarg);
            if (rollover_interval <= 0)
                usage(argv[0]);
            break;
        case 'h':
        default:
            usage(argv[0]);
        }
    }

    // make sure that stats interval is no longer than rollover interval
    stats_interval = stats_interval > rollover_interval ? rollover_interval : stats_interval;

    
    /* ********* SET UP CAPTURE ********* */
    pcap_t *pcap_handle = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    if (read_from_file)
    {
        pcap_handle = pcap_open_offline(input_file, errbuf);
    } 
    else
    {
#if HAVE_PCAP_CREATE
        pcap_handle = pcap_create(dev, errbuf);
        if (NULL == pcap_handle)
        {
            fprintf(stderr, "pcap_create failed: %s\n", errbuf);
            return -1;
        }

        if (pcap_set_promisc(pcap_handle, 1))
        {
            fprintf(stderr, "Setting promiscuous mode failed: %s\n", pcap_geterr(pcap_handle));
            return -1;
        }
        
        if (pcap_set_snaplen(pcap_handle, snaplen))
        {
            fprintf(stderr, "Setting snaplen of %d failed: %s\n", snaplen, pcap_geterr(pcap_handle));
            return -1;
        }

        if (pcap_set_timeout(pcap_handle, 1000))
        {
            fprintf(stderr, "Setting pcap timeout 1000 ms failed: %s\n", pcap_geterr(pcap_handle));
            return -1;
        }

#ifdef HAVE_PCAP_SET_BUFFER_SIZE
        if (pcap_set_buffer_size(pcap_handle, 1024*1024))
        {
            fprintf(stderr, "Couldn't set buffer size: %s\n", pcap_geterr(pcap_handle));
        }
#endif

        if (pcap_activate(pcap_handle) != 0)
        {
            fprintf(stderr, "pcap activate gave warning: %s\n", pcap_geterr(pcap_handle));
        }

#else
        pcap_handle = pcap_open_live(dev, snaplen, 1, 1000, errbuf);
#endif // HAVE_PCAP_CREATE
    }

    if (pcap_handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(EXIT_FAILURE);
    }
#if DEBUG
    fprintf(stderr, "Setup capture handle...\n");
#endif

    bpf_u_int32 netp = 0;
    bpf_u_int32 maskp = 0;
    if (pcap_lookupnet(dev, &netp, &maskp, errbuf) == -1)
    {
        fprintf(stderr, "Couldn't find net with device %s: %s\n", dev, errbuf);
        exit(EXIT_FAILURE);
    }
#if DEBUG
    fprintf(stderr, "Found net with device...\n");
#endif

    struct bpf_program filter_comp;
    if (pcap_compile(pcap_handle, &filter_comp, pcap_string, 1, maskp) == -1)
    {
        fprintf(stderr, "Couldn't compile filter expression \"%s\"\n", pcap_string);
        exit(EXIT_FAILURE);
    }

    if (pcap_setfilter(pcap_handle, &filter_comp) == -1)
    {
        fprintf(stderr, "Couldn't apply filter\n");
        exit(EXIT_FAILURE);
    }


    /* ********* START CAPTURE ********* */
    time_t current_time = 0, next_rollover = 0, update_time = 0;
    char output_file_path[MAXOUTNAME];
    char output_file[MAXOUTNAME];
    char dump_file[MAXOUTNAME];
    FILE *metadata_fh = NULL;
    pcap_dumper_t *savefile = NULL;
    uint64_t packet_count = 0ULL, saved_packet_count = 0ULL;
    srand48((unsigned int) time(NULL));
    double saved_kilobytes = 0;
    uint64_t byte_count = 0ULL, saved_byte_count = 0ULL;
    int files_written = 0;

    FILE *stats_fh = make_stats_file(exp_name);
    time_t stats_last = 0;

    if (start_count > 0)
    {
        packet_count = sample_rate - start_count - 1;
    }
    else
    {
        packet_count = 0;
    }

    /*
     * now prepare to store the packets. First check whether the given
     * path exists.
     */
    struct stat buf; 
    if (stat(output_path, &buf) == -1)
    {
        if (mkdir(output_path, 0777) == -1)
        {
            fprintf(stderr, "Couldn't access the given directory: %d/%s\n", errno, strerror(errno));
            return -1;
        }
    }

#if DEBUG
    fprintf(stderr, "Beginning timed capture...\n");
#endif

#if HAVE_PCAP_NEXT_EX
    struct pcap_pkthdr *header = NULL;
#else
    struct pcap_pkthdr header;
#endif
    const u_char *packet_data = NULL;

    int count_agg = 0;
#ifdef HAVE_YAF
    int flow_agg = 0;
    yfContext_t *yafcontext = NULL;
#endif
    if(aggoptstr != NULL)
    {
        if(!strcmp(aggoptstr,AGG_COUNT))
        {
            count_agg = 1;
        }
#ifdef HAVE_YAF
        else if (!strcmp(aggoptstr,AGG_FLOW))
        {
            flow_agg = 1;
            yafcontext = yafMakeContext(pcap_handle, dev);
        }
#endif
    }        
    int aggregation = count_agg;
#ifdef HAVE_YAF
    aggregation |= flow_agg;
#endif
    int timeout = 0;
    while (run_capture)
    {
        /* ********* GET NEXT PACKET ********* */
#if HAVE_PCAP_NEXT_EX
        timeout = 0;
        int rv = pcap_next_ex(pcap_handle, &header, &packet_data);
        if (rv < 0)
        {
            fprintf(stderr, "error occurred in pcap_next_ex: %d\n", rv);
            break;
        }  
        else if (rv == 0)
        {
            timeout = 1;
        }  
#else
        if ((packet_data = pcap_next(pcap_handle, &header)) == NULL)
        {
            /* 
             * in the absence of other information, assume a non-fatal 
             * error and a timeout.  using pcap_next_ex solves this issue.
             */
            timeout = 1;
        }
#endif

        if (timeout)
        {
            current_time = time(NULL);
        }
        else
        {
            /* record time for later use */
#if HAVE_PCAP_NEXT_EX
            current_time = header->ts.tv_sec;
            byte_count += header->len;
            saved_kilobytes += (double) header->len / 1024.;
#else
            current_time = header.ts.tv_sec;
            byte_count += header.len;
            saved_kilobytes += (double) header.len / 1024.;
#endif
            packet_count++;  
        }

        
        /* ********* OUTPUT FILE ROLLOVER ********* */
        /* check whether need to create a new file based on elapsed time */
        if (current_time >= next_rollover)
        {
            /* update files written counter.  add one for metadata
               file and one for data file, but only if flow
               aggregation or no aggregation at all */
	    if (metadata_fh != NULL)
	    {
		files_written += 1;
#if HAVE_YAF
		if (flow_agg || !count_agg)
#else
		if (!count_agg) 
#endif
		    files_written += 1;
	    }

            next_rollover = current_time + rollover_interval;

            if (savefile != NULL)
            {
                pcap_dump_flush(savefile);
                pcap_dump_close(savefile);
                savefile = NULL;
            }

            if (metadata_fh != NULL) 
            {
                if (start_count > 0)
                    packet_count -= sample_rate - start_count - 1;
                do_metadata_trailer(metadata_fh, current_time, packet_count, saved_packet_count, byte_count, saved_kilobytes, aggregation);
                fclose(metadata_fh);
                metadata_fh = NULL;
                update_completed_files(exp_name, dump_file);
            }

            next_stats = current_time + stats_interval; 

            strftime(timestamp, TSLEN, "%Y%m%d%H%M%S", gmtime(&current_time));
          
            snprintf(dump_file, MAXOUTNAME, "%s/%s_%s_%s%s", output_path, exp_name, gims_location,
                                            timestamp, "_metadump.xml");
            fprintf(stderr, "File rollover: metadata written to %s\n", dump_file);

            /*
             * If no aggregation, roll over the pcap output file
             */
            snprintf(output_file, MAXOUTNAME, "%s_%s_%s.%s", exp_name, gims_location, timestamp, aggregation?"yaf":"pcap");
            snprintf(output_file_path, MAXOUTNAME, "%s/%s", output_path, output_file);

            if (!aggregation)
            {
                if ((savefile = pcap_dump_open(pcap_handle, output_file_path)) == NULL)
                {
                    char *err = pcap_geterr(pcap_handle);
                    fprintf(stderr, "Couldn't open pcap savefile: %s \n", err);
                    return -1;
                }
            }
#if HAVE_YAF
            else if (flow_agg)
            {
                /*
                 * at rollover time, set new output file name in yafcontext
                 * and flush current output flow record file
                 */
                yafFlush(yafcontext);
                strncpy(yafcontext->cfg->outspec, output_file_path, 1024);
            }
#endif

            if ((metadata_fh = fopen(dump_file, "w")) == NULL) 
            {
                fprintf(stderr, "Couldn't open dump file");
                return -1;
            }

            do_metadata_header(metadata_fh, current_time, output_file, count_agg,
                               user_metadata, gims_location,
                               sample_type, sample_rate, exp_name, 
                               dev, pcap_string, rollover_interval, aggoptstr, anon_key);
            if (read_from_file)
                fprintf(metadata_fh,"\t\t<input_file>%s</input_file>\n", input_file);

        }

        /* ********* STATS DUMPAGE  ********* */
	time_t now = time(NULL);
	if (now > stats_last && stats_fh) 
	{
	    // dump stats at most every second
	    rewind(stats_fh);
	    fprintf(stats_fh, "totbytes %llu totpackets %llu bytespostsample %llu packetspostsample %llu files %d\n", byte_count, packet_count, saved_byte_count, saved_packet_count, files_written);
	    stats_last = now;
	}

        /* if there's a timeout, don't do anything else */
        if (timeout)
            continue;


        /* ********* PERIODIC METADATA CAPTURE STATS ********* */
        if (!read_from_file && current_time > next_stats)
        {
            next_stats = current_time + stats_interval;
            do_capture_stats(metadata_fh, pcap_handle, current_time, packet_count, byte_count);
        }


        /* ********* SAMPLING ********* */
        if (sample_type != SAMPLE_ALL)
        {
            /* check if should sample the packet */
            if (sample_type == SAMPLE_PROBABILITY) 
            {
                double rand_num = drand48();
                if (rand_num > sample_rate) 
                {
                    continue;
                }
            }

            /* Only skip if it is not the nth packet */
            if (sample_type == SAMPLE_TIME_INTERVAL) 
            {
                if (packet_count % (int) sample_rate != 0) 
                {
                    continue;
                }
            }
        }


        /* ********* ANONYMIZATION ********* */
#ifdef ANONYMIZE
        if (NULL != anon_key)
        {
            int ipoffset = SIZE_ETHERNET + (sizeof(struct ip) - 8);
            struct in_addr *ip_src = (struct in_addr*)(packet_data + ipoffset);
            struct in_addr *ip_dst = (struct in_addr*)(packet_data + ipoffset + 4);
            ip_src->s_addr = anonymize(ip_src->s_addr, (u_char*)anon_key);
            ip_dst->s_addr = anonymize(ip_dst->s_addr, (u_char*)anon_key);
        }
#endif
 

        /* ********* AGGREGATION ********* */
        /* NB: packet/byte count aggregation comes for free in metadata */
#if HAVE_YAF
        if (flow_agg)
        {
            yafAddPacketToFlow(yafcontext, header, packet_data);
        }
#endif

        /* ********* PACKET HEADER DUMP  ********* */
        if (!aggregation)
        {
#if HAVE_PCAP_NEXT_EX
            pcap_dump((u_char*)savefile, header, packet_data);
#else
            pcap_dump((u_char*)savefile, &header, packet_data);
#endif
            saved_packet_count++;
	    saved_byte_count += header->len;
        }

    } // end of main capture loop
    
    time_t now = time(NULL);
    pcap_freecode(&filter_comp);
   
    if (packet_count != 0) 
    {
        do_capture_stats(metadata_fh, pcap_handle, now, packet_count, byte_count);
        if (savefile)
        {
            pcap_dump_flush(savefile);
            pcap_dump_close(savefile);
        }
        pcap_close(pcap_handle);
        if (start_count > 0)
            packet_count -= sample_rate - start_count - 1;
        do_metadata_trailer(metadata_fh, now, packet_count, saved_packet_count, byte_count, saved_kilobytes, aggregation);
        fclose(metadata_fh);
        update_completed_files(exp_name, dump_file);
    }

#ifdef HAVE_YAF
    if (flow_agg)
    {
        yafFlush(yafcontext);
    }
#endif

    if (stats_fh) {
	fclose(stats_fh);
    }

    return 0;
}

void stop_capture(int signum)
{
    run_capture = 0;
}

#!/usr/local/bin/python3

"""
Load in trace records in CADETS json format and identify correlations between
events (possibly on different hosts)

Outputs json showing correlations

"""

import argparse
import json
import logging
import os
import subprocess
import sys
from time import sleep

import confluent_kafka

from correlator import Correlator

GROUP_ID = "CADETS_"+str(subprocess.getoutput(['sysctl -n kern.hostuuid']))
KAFKASTRING = "129.55.12.59:9092"
PRODUCER_ID = "cadets"
CA_CERT_LOCATION = "/var/private/ssl/ca-cert"
CERT_LOCATION = "/var/private/ssl/kafka.client.pem"
KEY_LOCATION = "/var/private/ssl/kafka.client.key"
KEY_PASSWORD = "TransparentComputing"
TOPIC = "cadets-raw-trace"

def get_arg_parser():
    parser = argparse.ArgumentParser(description="Add correlations between CADETS traces")
    parser.add_argument("-v", action="store_true", default=False,
                        help="Turn up verbosity.")
    parser.add_argument("files", action="store", type=str, nargs='+',
                        help="File to run correlation on")
    parser.add_argument("-window", action="store", type=int, default=50000000000,
                        help="Nanosecond time window for correlations (default 5ms)")
    kafka_settings = parser.add_argument_group('Kafka settings')
    kafka_settings.add_argument("-kafka", action="store_true", default=False,
                                help="Use Kafka for I/O")
    kafka_settings.add_argument("-kouts", action="store", default=KAFKASTRING,
                                required="-kafka" in sys.argv, help="Kafka connection string")
    kafka_settings.add_argument("-kins", action="store", default=KAFKASTRING,
                                required="-kafka" in sys.argv, help="Kafka connection string")
    kafka_settings.add_argument("-kouttopic", action="store", type=str, default=TOPIC,
                                required="-kafka" in sys.argv, help="Kafka topic to publish to")
    kafka_settings.add_argument("-kintopic", action="store", type=str, default=TOPIC,
                                required="-kafka" in sys.argv, help="Kafka topic to publish to")
    kafka_settings.add_argument("-kinssl", action="store_true", default=False,
                                help="Use SSL for kafka input")
    kafka_settings.add_argument("-koutssl", action="store_true", default=False,
                                help="Use SSL for kafka input")
    return parser


def main():
    parser = get_arg_parser()
    args = parser.parse_args()

    producer = None
    if args.kafka:
        pconfig = {}
        pconfig["bootstrap.servers"] = args.kouts
        pconfig["api.version.request"] = True
        pconfig["client.id"] = PRODUCER_ID
        if args.koutssl:
            pconfig["ssl.ca.location"] = CA_CERT_LOCATION
            pconfig["ssl.certificate.location"] = CERT_LOCATION
            pconfig["ssl.key.location"] = KEY_LOCATION
            pconfig["ssl.key.password"] = KEY_PASSWORD
            pconfig["security.protocol"] = "ssl"
        producer = confluent_kafka.Producer(pconfig)

        cconfig = {}
        cconfig["bootstrap.servers"] = args.kins
        cconfig["api.version.request"] = True
        cconfig["group.id"] = GROUP_ID
        cconfig["default.topic.config"] = {"auto.offset.reset": "beginning"}
        if args.kinssl:
            cconfig["ssl.ca.location"] = CA_CERT_LOCATION
            cconfig["ssl.certificate.location"] = CERT_LOCATION
            cconfig["ssl.key.location"] = KEY_LOCATION
            cconfig["ssl.key.password"] = KEY_PASSWORD
            cconfig["security.protocol"] = "ssl"
        consumer = confluent_kafka.Consumer(cconfig)
        consumer.subscribe([args.kintopic])
        analyse_kafka(consumer, args.v, args.window, producer, args.kouttopic)
    else:
        # Load the input files
        analyse_files(list(map(os.path.expanduser, args.files)), args.v, args.window)

def analyse_files(paths, _verbosity, time_window):
    correlator = Correlator(time_window)
    trace = {}
    relevant_lines = {}

    for path in paths:
        trace[path] = open(file=path, mode='r', buffering=1, errors='ignore')

    for path in paths:
        # map and filter return iterators - they don't do everything at once.
        lines = map(file_line_to_json, trace[path])
        relevant_lines[path] = list(filter(correlator.event_filter, lines))
        for line in relevant_lines[path]:
            correlator.key_event(line)

    # for event in all-events, search for event with key matching local addr/port
    for path in paths:
        # map and filter return iterators - they don't do everything at once.
        lines = map(file_line_to_json, trace[path])
        relevant_lines[path] = list(filter(correlator.event_filter, lines))
        for line in relevant_lines[path]:
            correlator.key_event(line)
            # Link events
            for(time, host1, uuid1, host2, uuid2, reason) in correlator.link_events(line):
                result = '{"timestamp":'+ str(time) + ', "host1":"' + host1 + '", "uuid1":"' + uuid1 + '", "host2":"' + host2 + '", "uuid2":"' + uuid2 + '", "reason":"' + reason + '"}'
                print(result)

    for path in paths:
        trace[path].close()

def analyse_kafka(consumer, _verbosity, time_window, producer, out_topic):

    correlator = Correlator(time_window)
    count = 0

    while 1:
        try:
            raw_cadets_record = consumer.poll(timeout=20)
            if raw_cadets_record and not raw_cadets_record.error():
                line = raw_cadets_record.value()
                correlator.key_event(line)
                for link in correlator.link_events(line):
                    result = correlation_tuple_to_string(link)
                    if producer:
                        producer.produce(out_topic, value=result, key=str(count).encode())
                        producer.poll(0)
                        count += 1
            if not raw_cadets_record:
                sleep(10)
            else:
                # was a kafka error message
                pass
        except KeyboardInterrupt: # handle ctrl+c
            break

    consumer.close()
    producer.flush()

def correlation_tuple_to_string(link):
    (time, host1, uuid1, host2, uuid2, reason) = link
    return '{"event":"cadets::correlator:", "timestamp":'+ str(time) + ', "host1":"' + host1 + '", "uuid1":"' + uuid1 + '", "host2":"' + host2 + '", "uuid2":"' + uuid2 + '", "reason":"' + reason + '"}'

def file_line_to_json(line):
    try:
        return json.loads(line)
    except ValueError as err:
        if line and line.strip():
            logging.error("invalid cadets entry \""+line+"\", error was: " + str(err))
        return None

if __name__ == '__main__':
    main()

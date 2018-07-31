#!/usr/local/bin/python3

"""
Load in trace records in CADETS json format and identify correlations between
events (possibly on different hosts)

Outputs json showing correlations

"""

import argparse
import os
import json
import logging
from collections import defaultdict

from correlator import Correlator

def get_arg_parser():
    parser = argparse.ArgumentParser(description="Add correlations between CADETS traces")
    parser.add_argument("-v", action="store_true", default=False,
                        help="Turn up verbosity.")
    parser.add_argument("files", action="store", type=str, nargs='+',
                        help="File to run correlation on")
    parser.add_argument("-window", action="store", type=int, default=50000000000,
                        help="Nanosecond time window for correlations (default 5ms)")
    return parser


def main():
    parser = get_arg_parser()
    args = parser.parse_args()

    # Load the input files
    # TODO do we need to expanduser? Not on OSX, but what about FreeBSD, etc?
    analyse_files(list(map(os.path.expanduser, args.files)), args.v, args.window)


def analyse_files(paths, verbosity, time_window):

    correlator = Correlator(time_window)
    trace = {}
    filtered_events = {}

    for path in paths:
        trace[path] = open(file=path, mode='r', buffering=1, errors='ignore')

    for path in paths:
        # map and filter return iterators - they don't do everything at once.
        lines = map(file_line_to_json, trace[path])
        relevant_lines = filter(correlator.event_filter, lines)
        filtered_events[path] = map(correlator.key_event, relevant_lines)

    keyed_events = []
    for path in paths:
        keyed_events.extend(filtered_events[path])

    keyed_events_dict = defaultdict(list)
    for key, values in keyed_events:
        if key:
            keyed_events_dict[key].append(values)

    # for event in all-events, search for event with key matching local addr/port
    # Link events
    results = []
    for (_, event) in keyed_events:
        results.extend(correlator.link_events(event, keyed_events_dict))

    for (uuid1, uuid2, reason) in results:
        print('{"uuid1":"'+uuid1+'", "uuid2":"'+uuid2+'", "reason":"'+reason+'"}')

    for path in paths:
        trace[path].close()

def file_line_to_json(line):
    try:
        return json.loads(line[2:])
    except ValueError as err:
#         if line:
#             logging.error("Invalid CADETS entry \""+line+"\", error was: " + str(err))
        return None

if __name__ == '__main__':
    main()
CADETS Correlation
==================

Running the correlator
----------------------

To identify correlations in a set of traces (currently only correlated sockets), 

```
python3 cadets_correlator.py [traces] > correlations.json
```

The correlator can take files as input, printing correlations to stdout (as
above), or can be used with Kafka. File and kafka I/O are mutually exclusive.

To use with kafka, the command would be:

```
python3 cadets_correlator.py -kafka -kouts localhost:9092 -kins localhost:9092 -kouttopic test-cadets4 -kintopic test-cadets4
```

Note that the kafka information for both input and output must be specified
even if they are identical. The correlator _can_ consume and publish to the
same topic without issue.


Adding correlators
------------------

Though untested, it should be possible to add additional correlators, either by
mapping through all correlators in `analyse_files`, or creating a master
correlator that combines the methods defined in `correlator.py`.

Remaining work
--------------

If event UUIDs are added to CADETS traces, then the correlator could be
improved by including event information in the correlation. This could be used
as justifying evidence for the correlation.

For testing purposes, it might be useful to allow mixing and matching input and
output streams (between files and kafka).

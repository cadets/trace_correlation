CADETS Correlation
==================

Running the correlator
----------------------

To identify correlations in a set of traces (currently only correlated sockets), 

```
python3 cadets_correlator.py [traces] > correlations.json
```


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


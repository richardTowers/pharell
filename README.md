PcapHarHa
=============

`PcapHarHa` converts pcaps to HARs. It's similar to [pcap2har](https://github.com/andrewf/pcap2har), only it's written in Haskell instead of Python.

Usage
-------------

Basically:

```
$ pcapharha capture.pcap > capture.har
```

It can also be used in a kind of "Streaming" mode, in which it will only output the `entries` separated by newlines. This is useful if
you want to analyse HTTP requests / responses as part of a live capture:

```
$ tcpdump -w - | pcapharha --stream
{ "startedDateTime": "2009-04-16T12:07:23.000Z", "time": 50, "request": {...}, "response": {...}, ... }
{ "startedDateTime": "2009-04-16T12:07:24.000Z", "time": 51, "request": {...}, "response": {...}, ... }
{ "startedDateTime": "2009-04-16T12:07:25.000Z", "time": 48, "request": {...}, "response": {...}, ... }
{ "startedDateTime": "2009-04-16T12:07:26.000Z", "time": 52, "request": {...}, "response": {...}, ... }
{ "startedDateTime": "2009-04-16T12:07:27.000Z", "time": 57, "request": {...}, "response": {...}, ... }
...
```

Note: some parts of the HAR (e.g. pages) can't be established from the pcap file easily. These are omitted.

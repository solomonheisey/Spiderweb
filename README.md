# Spiderweb

## Motivation

In the era of IoT devices, it is no secret that these devices collect user data. The volume and velocity of network traffic sent from these devices are often unknown to the consumer. While tools such as Wireshark and Kismet exist, they are not designed for the average user; incorporating features designed for professionals. This project aims to create a 3rd party device that intercepts network packets transmitted from the given IoT device. Network traffic is used as a proxy for activity such as recording and transmitting. The problem being solved is a lack of clear interfaces designed for people to know what their IoT devices are doing. The information returned from the program is conveyed to the user through the aid of an ambient interface. The ambient interface, in this case, being an RGB smart lightbulb. Using an ambient interface in this project is critical. The program automates a very abstract process and presents it to the user in a way that does not overinform them and cause them to lose attention. The goal of this research is to create a device designed for the average consumer. It also aims to make people more aware of times when they might be unknowingly surveilled. Simplifying data privacy and designing a product that would fit in any space are two central facets of this project.


## Getting Started

Spiderweb has only been tested on Linux-based systems. To run the program, follow the install procedure below.

Notes:
* At least two network cards are required. A secondary network card is mandatory since one is placed into monitored mode in order to sniff network packets and one is used to communicate with the Lifx lightbulbs.
* As of now, this program only works on Lifx lightbulbs. All devices must be registered to a network and fully setup in order to use the full functionality of the program.

```
$ pip install -r requirements.txt
$ sudo python Spiderweb.py
```
Needs to be run with sudo because we're doing system-level stuff. For some reason scapy won't work within a virtual environment.

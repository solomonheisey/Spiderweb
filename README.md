# Spiderweb

## Motivation

In the era of Internet of things (IoT) devices, it is no secret that these devices collect user data.  The lack of clear interfaces to understand device activity is a problem which plagues nearly every connected device.  The volume and velocity ofnetwork traffic sent from these devices are often unknown to the consumer. While network protocol analyzing tools suchas Wireshark and Kismet exist, they are not designed for the average user. This research project aims to create a third party device that intercepts network packets transmitted from a given IoT device. Network traffic is used as a proxy for activity suchas recording and transmitting data.  We propose an ambient interface to convey the network traffic information to the user to tackle the challenge of lack of clarity in user interfaces. The ambient interface, in this case, being an RGB smart light bulb. Using an ambient interface in this project is critical since it conveys an complex concept in an intuitive manner. The program automates an abstract process and presents it to the user in a way that does not over-inform them and cause them to lose attention.  The goal of this research is to make people more aware of times when they might be unknowingly surveilled. We achieve this goal by creating a device designed for the average consumer. Simplifying data privacy and designing aproduct that would fit in any space are two central facets of this project.


## Getting Started

Spiderweb has only been tested on Linux-based systems. To run the program, follow the install procedure below.

Notes:
* At least two network cards are required. A secondary network card is mandatory since one is placed into monitored mode in order to sniff network packets and one is used to communicate with the Lifx lightbulbs.
* As of now, this program only works on Lifx lightbulbs. All devices must be registered to a network and fully setup in order to use the full functionality of the program.

```
$ xargs sudo apt-get install < install/requirements.system
$ pip install -r install/requirements.txt
$ sudo python src/application/Spiderweb.py
```
Needs to be run with sudo because we're doing system-level stuff. For some reason scapy won't work within a virtual environment.

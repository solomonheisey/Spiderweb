# Spiderweb
## Connected IoT Device Monitoring via Network Traffic Analysis

In the era of IoT devices, it is no secret that these devices collect user data. The volume and velocity of network traffic sent from these devices are often unknown to the consumer. While tools such as Wireshark and Kismet exist, they are not designed for the average user; incorporating features designed for professionals. This project aims to create a 3rd party device that intercepts network packets transmitted from the given IoT device. Network traffic is used as a proxy for activity such as recording and transmitting. The problem being solved is a lack of clear interfaces designed for people to know what their IoT devices are doing. The information returned from the program is conveyed to the user through the aid of an ambient interface. The ambient interface, in this case, being an RGB smart lightbulb. Using an ambient interface in this project is critical. The program automates a very abstract process and presents it to the user in a way that does not overinform them and cause them to lose attention. The goal of this research is to create a device designed for the average consumer. It also aims to make people more aware of times when they might be unknowingly surveilled. Simplifying data privacy and designing a product that would fit in any space are two central facets of this project.


## Running

Spiderweb has only been tested on Linux-based systems. To run the program, follow the install procedure below. Note: a secondary network card is required for the program to work since a network card must be placed into monitored mode in order for the program to sniff packets.
```
$ pip install -r requirements.txt
$ sudo python Spiderweb.py
```
Needs to be run with sudo because we're doing system-level stuff. For the some reason scapy won't work within a virtual environment.

from flask import Flask, render_template_string, render_template
import requests
import json
import xml.etree.ElementTree as ET
import re
from requests.auth import HTTPBasicAuth

app = Flask(__name__, static_folder='core/static/', static_url_path='/core/static/', template_folder='templates')

# Switchkonfiguration
SWITCH = {
    "host": "",  # Ändra till switchens IP-adress
    "username": "admin",  # Användarnamn
    "password": "cisco"  # Lösenord
}

# RESTCONF-header
HEADERS = {
    "Accept": "application/yang-data+xml"
}

# Funktion för naturlig sortering
def natural_sort_key(interface_name):
    return [int(text) if text.isdigit() else text.lower() for text in re.split(r'(\d+)', interface_name)]

def get_hostname():
    """Hämtar hostname från enheten via RESTCONF."""
    url = f"https://{SWITCH['host']}/restconf/data/Cisco-IOS-XE-native:native/hostname"
    try:
        response = requests.get(url, headers={"Accept": "application/yang-data+json"}, auth=HTTPBasicAuth(SWITCH["username"], SWITCH["password"]), verify=False)
#        response = requests.get(url, headers=HEADERS, auth=HTTPBasicAuth(SWITCH['username'], SWITCH['password']), verify=False)
        if response.status_code == 200:
            data = response.json()
            # Hämta hostname från JSON-responsen
            hostname = data.get("Cisco-IOS-XE-native:hostname")
            return hostname
        else:
            print(f"Fel vid hämtning av hostname: HTTP {response.status_code}")
            return("feL")
    except Exception as e:
        print(f"Ett fel inträffade vid hämtning av hostname: {e}")
        return (e)

# Hämta provision från switch
def get_provision():
    """Hämtar provision från enheten via RESTCONF och bearbetar XML-responsen."""
    url = f"https://{SWITCH['host']}/restconf/data/Cisco-IOS-XE-native:native/switch"

    try:
        response = requests.get(url, headers={"Accept": "application/yang-data+xml"},
                                auth=HTTPBasicAuth(SWITCH["username"], SWITCH["password"]), verify=False)
        if response.status_code == 200:
            # Bearbeta XML-svaret
            root = ET.fromstring(response.text)
            # Namespace för XML
            namespace = {"ios-sw": "http://cisco.com/ns/yang/Cisco-IOS-XE-switch"}
            # Hämta provision från XML-responsen
            provision = root.find("ios-sw:provision", namespace)
            return provision.text if provision is not None else "Unknown"
        else:
            print(f"Fel vid hämtning av provision: HTTP {response.status_code}")
            return "Unknown"
    except Exception as e:
        print(f"Ett fel inträffade vid hämtning av provision: {e}")
        return "Unknown"

# Hämta routingprotokoll
def get_routing_protocols():
    url = f"https://{SWITCH['host']}/restconf/data/Cisco-IOS-XE-native:native/router"

    try:
        response = requests.get(url, headers=HEADERS, auth=(SWITCH['username'], SWITCH['password']), verify=False)
        response.raise_for_status()
        xml_data = response.text

        # Bearbeta XML för routingprotokoll
        root = ET.fromstring(xml_data)
        namespaces = {
            "ios": "http://cisco.com/ns/yang/Cisco-IOS-XE-native",
            "ospf": "http://cisco.com/ns/yang/Cisco-IOS-XE-ospf"
        }

        protocols = []

        # Leta efter OSPF-konfiguration
        ospf = root.find("ospf:router-ospf/ospf:ospf", namespaces)
        if ospf is not None:
            process_id = ospf.find("ospf:process-id/ospf:id", namespaces)
            router_id = ospf.find("ospf:process-id/ospf:router-id", namespaces)
            networks = ospf.findall("ospf:process-id/ospf:network", namespaces)

            ospf_info = {
                "protocol": "OSPF",
                "process_id": process_id.text if process_id is not None else "Unknown",
                "router_id": router_id.text if router_id is not None else "Unknown",
                "networks": []
            }

            for network in networks:
                ip = network.find("ospf:ip", namespaces)
                wildcard = network.find("ospf:wildcard", namespaces)
                area = network.find("ospf:area", namespaces)
                ospf_info["networks"].append({
                    "ip": ip.text if ip is not None else "Unknown",
                    "wildcard": wildcard.text if wildcard is not None else "Unknown",
                    "area": area.text if area is not None else "Unknown"
                })

            protocols.append(ospf_info)

        return protocols
    except requests.exceptions.RequestException as e:
        print(f"Error fetching routing protocols: {e}")
        return []

# Funktion för att hämta interfaces
def get_all_interfaces():
    interfaces_url = f"https://{SWITCH['host']}/restconf/data/ietf-interfaces:interfaces"

    try:
        response = requests.get(interfaces_url, headers={"Accept": "application/yang-data+json"}, auth=(SWITCH['username'], SWITCH['password']), verify=False)
        response.raise_for_status()
        interfaces = response.json().get("ietf-interfaces:interfaces", {}).get("interface", [])

        interface_details = []
        for iface in interfaces:
            ipv4_addresses = [
                f"{ip['ip']}/{ip['netmask']}" for ip in iface.get("ietf-ip:ipv4", {}).get("address", [])
            ]
            interface_details.append({
                "name": iface.get("name", "Unknown"),
                "description": iface.get("description", "No description"),
                "ip": ", ".join(ipv4_addresses) if ipv4_addresses else "No IP",
                "status": "Enabled" if iface.get("enabled", False) else "Disabled"
            })

        # Sortera interfaces med naturlig ordning
        interface_details.sort(key=lambda x: natural_sort_key(x["name"]))

        return interface_details
    except requests.exceptions.RequestException as e:
        print(f"Error fetching interfaces: {e}")
        return []

def get_vlans():
    vlan_url = f"https://{SWITCH['host']}/restconf/data/Cisco-IOS-XE-native:native/vlan/Cisco-IOS-XE-vlan:vlan-list"

    try:
        response = requests.get(vlan_url, headers={"Accept": "application/yang-data+json"}, auth=(SWITCH['username'], SWITCH['password']), verify=False)
        response.raise_for_status()
        vlans = response.json().get("Cisco-IOS-XE-vlan:vlan-list", [])

        vlan_details = []
        for vlan in vlans:
            vlan_details.append({
                "id": vlan.get("id", "Unknown"),
                "name": vlan.get("name", "No name"),
                "interfaces": ", ".join(vlan.get("interfaces", {}).get("interface", []))
            })

        return vlan_details
    except requests.exceptions.RequestException as e:
        print(f"Error fetching VLANs: {e}")
        return []


@app.route("/test")
def test():
    return render_template('switch.html')
@app.route("/<ip>")
def index(ip):
    SWITCH["host"] = ip
    hostname = get_hostname()
    provision = get_provision()
    protocols = get_routing_protocols()
    interfaces = get_all_interfaces()
    vlans = get_vlans()
    if "c9300" in provision.lower():
        return render_template('switch.html', hostname=hostname, vlans=vlans, provision=provision, protocols=protocols, interfaces=interfaces)
    else:
        return("fel")
# Starta Flask-applikationen
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")

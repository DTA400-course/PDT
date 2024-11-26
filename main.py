from flask import Flask, render_template_string
import requests
import json
import xml.etree.ElementTree as ET
import re
from requests.auth import HTTPBasicAuth

app = Flask(__name__, static_folder='core/static/', static_url_path='/core/static/', template_folder='/core/template')

# Switchkonfiguration
SWITCH = {
    "host": "192.168.1.1",  # Ändra till switchens IP-adress
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

def get_provision():
    """Hämtar provision eller PID från enheten via RESTCONF och bearbetar XML-responsen."""
    urlSwitch = f"https://{SWITCH['host']}/restconf/data/Cisco-IOS-XE-native:native/switch"
    urlRouter = f"https://{SWITCH['host']}/restconf/data/Cisco-IOS-XE-native:native/license/udi"

    try:
        # Försök att hämta från switch-URL
        responseSwitch = requests.get(urlSwitch, headers={"Accept": "application/yang-data+xml"},
                                      auth=HTTPBasicAuth(SWITCH["username"], SWITCH["password"]),
                                      verify=False)

        if responseSwitch.status_code == 200:
            # Bearbeta XML-svaret för Switch
            root = ET.fromstring(responseSwitch.text)
            namespace = {"ios-sw": "http://cisco.com/ns/yang/Cisco-IOS-XE-switch"}
            provision = root.find("ios-sw:provision", namespace)
            return provision.text.strip() if provision is not None else "Unknown"

        # Om Switch-URL inte svarar, försök med Router-URL
        responseRouter = requests.get(urlRouter, headers={"Accept": "application/yang-data+xml"},
                                      auth=HTTPBasicAuth(SWITCH["username"], SWITCH["password"]),
                                      verify=False)

        if responseRouter.status_code == 200:
            # Bearbeta XML-svaret för Router
            root = ET.fromstring(responseRouter.text)
            namespace = {"ns": "http://cisco.com/ns/yang/Cisco-IOS-XE-native"}
            pid_element = root.find(".//ns:pid", namespace)
            return pid_element.text.strip() if pid_element is not None else "PID not found"

        # Om ingen av URL:erna svarade
        return "No valid response from either URL"

    except Exception as e:
        print(f"Ett fel inträffade vid hämtning av provision: {e}")
        return "Unknown"


def get_image():
    """Hämtar provision från enheten via RESTCONF och bearbetar XML-responsen."""
    url = f"https://{SWITCH['host']}/restconf/data/Cisco-IOS-XE-native:native/switch"

    try:
        response = requests.get(url, headers={"Accept": "application/yang-data+xml"}, auth=HTTPBasicAuth(SWITCH["username"], SWITCH["password"]), verify=False)
        if response.status_code == 200:
            # Bearbeta XML-svaret
            root = ET.fromstring(response.text)
            # Namespace för XML
            namespace = {"ios-sw": "http://cisco.com/ns/yang/Cisco-IOS-XE-switch"}
            # Hämta provision från XML-responsen
            provision = root.find("ios-sw:provision", namespace)
            img = "switch.jpg"
            return img
        else:                                     
            img = "router.jpg"
            return img
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

@app.route("/")
def index():
    hostname = get_hostname()
    provision = get_provision()
    protocols = get_routing_protocols()
    interfaces = get_all_interfaces()
    #vlans = get_vlans()
    #image = get_image()

    if "4321" in provision:
        image = "router.jpg"
    else:
        image = "switch.jpg"

    html_template = """
<!DOCTYPE html>
<html>
<head>
    <title>Switch Information</title>
    <style>
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            border: 1px solid black;
            padding: 8px;
            text-align: left;
        }
        th {
            background-color: #f2f2f2;
        }
        img {
            display: block;
            margin: 10px auto;
            max-width: 100%;
            height: auto;
        }
    </style>
<script>
        // Funktion för att uppdatera innehållet var 10:e sekund
        function refreshContent() {
            fetch(window.location.href)
                .then(response => response.text())
                .then(data => {
                    // Uppdatera hela sidinnehållet
                    document.open();
                    document.write(data);
                    document.close();
                })
                .catch(error => console.error("Error fetching content:", error));
        }

        // Kör refreshContent varje 10:e sekund
        setInterval(refreshContent, 100000);
    </script>
</head>

<body>
    <h1>Switch Information</h1>

    <h2>Hostname: {{ hostname }}</h2>
    <h2>Provision: {{ provision }}</h2>

    <!-- Bilder ovanför Interfaces -->
    <div>
        <img src="{{ url_for('static', filename='img/' + image) }}" alt="Image 1">
    </div>

    <h2>Interfaces</h2>
    <table>
        <tr>
            <th>Interface Name</th>
            <th>Description</th>
            <th>IP Address</th>
            <th>Status</th>
        </tr>
        {% for interface in interfaces %}
        <tr>
            <td>{{ interface.name }}</td>
            <td>{{ interface.description }}</td>
            <td>{{ interface.ip }}</td>
            <td>{{ interface.status }}</td>
        </tr>
        {% endfor %}
    </table>
    <h2>Routing Protocols</h2>
    <table>
        <tr>
            <th>Protocol</th>
            <th>Process ID</th>
            <th>Router ID</th>
            <th>Networks</th>
        </tr>
        {% for protocol in protocols %}
        <tr>
            <td>{{ protocol.protocol }}</td>
            <td>{{ protocol.process_id }}</td>
            <td>{{ protocol.router_id }}</td>
            <td>
                <ul>
                {% for network in protocol.networks %}
                    <li>{{ network.ip }} (Wildcard: {{ network.wildcard }}, Area                                     : {{ network.area}})</li>
                {% endfor %}
                </ul>
            </td>
        </tr>
        {% endfor %}
    </table>
</body>
</html>

    """
    return render_template_string(html_template, hostname=hostname, provision=provision, protocols=protocols, interfaces=interfaces, image=image)

# Starta Flask-applikationen
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")

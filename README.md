# PDT
Det som skall göras är att skapa en template för routern då den inte har någon vlan funktion

Main.py tar rätt bild men har inte stöd för vlan i dess index, men visar interfaces, ip, status, desc och protokol(kan ta bort protokoll om det önskas)

Dynamic.py fungerar för switchen så att det går att ta "https://{server_ip}:5000/{enhet-ip}" och den tar från en template men får bara fixa så att den tar en router template (det är såhär vi får qr koden sen att fungera)

Pages.py är som main.py fast den använder switch template ifall modellnumret är 9300 (L3 switch)

ska uppdateras automatiskt, i template sattes väldigt hög tid men annars är den på 10 sek

requierments:
* sätt på ospf annars kommer error (kanske därför ta bort)
* skapa användare admin med lösen cisco med priv 15
* sätt på http server, secure-server, och auithenticate med local
* på main och pages måste enhets adressen vara 192.168.1.1 på dynamic kan man välja själv
  

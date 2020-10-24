# router-simulator


TEMA 1 - PROTOCOALE DE COMUNICATIE - Implementarea procesului de dirijare a pachetelor intr-un router in mai multi pasi:

	- Parsarea tabelei de rutare:
	- Cautarea in tabela de rutare: 
		- problema: numarul de intrari din fisierul rtable.txt era foarte mare, 
		deci o cautare liniara in vectorul de intrari nu ar fi fost deloc eficienta
		- solutie: am realizat o sortare dupa prefix si, in cazul in care prefixele 
		sunt egale, dupa masca, apoi am implementat cautarea celei mai specifice intrari 
		din tabela de rutare utilizand algoritmul binary search putin modificat
		- cand gasesc o intrare care face match, continui sa ma uit la intrarile 
		urmatoare pana cand gasesc prima intrare care nu mai face match
		- faptul ca am sortat crescator in prealabil dupa prefix si masca imi 
		garanteaza ca ultima intrare care a facut match este cea mai specifica intrare 
		din tabela de rutare
	
	- Intr-o bucla infinita, routerul primeste pachete si le trateaza diferit in functie de informatiile continute in headere:
	1. Primeste un pachet de la oricare din interfetele adiacente.
	2. Daca este un pachet IP destinat routerului, raspunde doar in cazul in care acesta este unpachet ICMP ECHO request. Arunca pachetul original.
	3. Daca este un pachet ARP Request catre un IP al routerului, raspunde cu ARP Reply cuadresa MAC potrivita.
	4. Daca este un pachet ARP Reply, updateaza tabela ARP; daca exista pachete ce trebuiedirijate catre acel router, transmite-le acum.
	5. Daca este un pachet cu TTL <= 1, sau un pachet catre o adresa inexistenta in tabela derutare, trimite un mesaj ICMP corect sursei (vezi mai jos); arunca pachetul.
	6. Daca este un pachet cu checksum gresit, arunca pachetul.
	7. Decrementeaza TTL, updateaza checksum.
	8. Cauta intrarea cea mai specifica din tabela de rutare (numita f) astfel incat (iph−>daddr&f.mask==f.prefix). Odata identificata, aceasta specifica next hop pentru pa-chet. In cazul in care nu se gaseste o ruta, se trimite un mesaj ICMP sursei; aruncapachetul
	9. Modifica adresele source si destination MAC. Daca adresa MAC nu este cunoscuta local,genereaza un ARP request si transmite pe interfata destinatie. Salveaza pachetul in coadapentru transmitere. atunci cand adresa MAC este cunoscuta (pasul 4).
	10. Trimite pachetul mai departe folosind functia send_packet(...).


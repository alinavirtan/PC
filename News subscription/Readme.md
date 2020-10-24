
# news-subscription

    Implementarea unei platforme in care exista 3 componente:
    •Severul(unic): realizeaza legatura intre clientii din platforma, cu scopul publicarii si abonarii la mesaje.
    •Clientii TCP: un client TCP se conecteaza la server, poate primi (in orice moment) de la tastatura(interactiunea cu utilizatorul  uman)  comenzi  de  tipul subscribe si unsubscribe si  afiseaza pe ecran mesajele primite de la server.
    •Clientii  UDP: publica, prin trimiterea catre server, mesaje in platforma propusa folosind un protocol predefinit. 

    Functionalitatea implica faptul ca fiecare client TCP primeaste de la server acele mesaje, venite de la clientii UDP, care fac referire la topic-urile la care sunt abonati.  Arhitectura include si o component de SF(store&forward) cu privire la mesajele trimise atunci cand clientii TCP sunt deconectati.

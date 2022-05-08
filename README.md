VYGENEROVAT TREE ZO ZLOZKY

### PARSOVANIE ARGUMENTOV

zadat je mozne len jeden mod -- povinne
kazdy mod si vyzaduje nejaku podmnozinu optional args - popisane v ?help?
cestu k suboru je mozne zadat aj relativnu, aj absolutnu
do uvahy sa beru len options relevantne pre dany mod, ostatne sa ignoruju
akykolvek arg je mozne zadat viackrat, pouzije sa posledna zadana hodnota (plati okrem modu)
v pripade nezadanych args program printne help a ukonci sa
pri zadani --version alebo --help sa vsetky ostatne args neberu do uvahy
ak sa zada aj -V aj -h, prve zadane plati
cover a stego files musia byt binarne programy formatu ELF alebo PE, ine nie -- vyskoci error

secret message moze byt akakolvek postupnost bajtov (text, subor atd.)
defaultne je secret message ocakavana na stdin, preto ju nie je nutne zadat cez option ani v pripade embed modu, ktory si ju vyzaduje (ako jediny).
 - ak je SEC MESS zadana na stdin, extrahovana bude ako text do suboru s priponou .txt
avsak je mozne ju zadat aj cez option (-s):
 - ak je zadana cesta k suboru a existuje, vkladat sa bude subor a extrahuje sa s prislusnou priponou.
 - ak nejde o cestu, vkladat sa bude retazec definujuci text a extrahuje sa do .txt
 - option ma vzdy prednost pred stdin.
 ak sa zrusi vstup na stdin bez akehokolvek vlozeneho znaku alebo sa vlozi "", nic sa nevklada/nedeje; program sa korektne ukonci.

### embedding

kompresia pouzita xz algo LZMA lebo ma vysoku kompresnu silu, je stredne rychla a pomerne dostupna pre unix (v prvom rade najvyssi kompresny pomer).

### extracting



### ERROR CODES:
2 error from argparse internal parsing
100 error caused wrong set of options - args_parser.py
101 - disassembler error
102 - selector error
103 - eq_classes_processor
104 - embedder error
105 - extractor error
109 - common error

OPRAVIT V PROGRAME - verbose vypnut pri analyze mode, pri verbose vypisat cas behu programu? zmenit desatinne nuly pri vypise analyze na max 3, nie min.. nechcem mat .500, mozno dodat do analyzy sucet vsetkych bajtov kodovych sekcii? aby som zistal data rate.

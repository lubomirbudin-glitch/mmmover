# Offload Proof — ukotvení offloadu v čase

19. 11. 2026 · L. Budin · *zadání funkce (vize pro všechny fáze). Co je z ní hotové a jak přesně to vypadá na disku,
říká [FORMATY.md](FORMATY.md) (oddíl Offload Proof) a návrh MVP
[windows/docs/superpowers/specs/2026-11-19-offload-proof-design.md](../windows/docs/superpowers/specs/2026-11-19-offload-proof-design.md).*

## Shrnutí

Offload Proof je funkce Offloadu, která ke každému offloadu karet vytvoří kryptografický důkaz: tyto soubory existovaly
přesně v tomto stavu nejpozději v čase T a od té doby se v nich nezměnil ani bajt. Důkaz stojí na dvou nezávislých
ukotveních. OpenTimestamps (Bitcoin) je zdarma a nezávislé na jakékoli firmě, kvalifikované časové razítko podle eIDAS
má v EU zákonnou domněnku správnosti.

Z počítače odchází jen 32bajtový hash, nikdy obsah ani názvy souborů. Funkce proto sedí i na produkce pod NDA.

Věta pro zákazníka: „Kdykoli v budoucnu doložíte, že vaše záběry existovaly v den natáčení a nikdo na ně nesáhl.“

Co to není: důkaz, že záběr zachycuje skutečnost, ani přesný čas stisknutí REC. To umí jen podpis přímo v kameře
(C2PA); Offload ho zachová, ověří a zapíše do manifestu.

## Proč teď a kde je mezera

Ukotvení médií už existuje pro fotky z mobilu a pro novináře, pro filmové karty a offload ne. To je mezera, do které
Offload vstupuje.

- **Mobilní kamery s ukotvením.** ProofSnap od Numbers Protocol vkládá do snímků C2PA a zároveň záznam na vlastní
  blockchain; cílí na novináře, pojistné likvidátory a právníky. Podobně Nodle Click a ProofMode.
- **Výrobci telefonů.** Google přidává C2PA i pro video na Pixel 8, 9 a 10 a ověření C2PA do Gemini, později do
  Vyhledávání a Chrome (Google, 19. 5. 2026). S mobilem tedy nemá smysl soupeřit.
- **Profi kamery.** Sony podepisuje video přes C2PA na α1 II, α1, α9 III, α7R V, α7S III, α7 IV, FX3, FX30 a PXW-Z300,
  ale jen MP4 do 222 Mb/s, bez 8K a zpomalení, a jako placenou službu v betaverzi (RedShark News, 13. 3. 2026). Mimo
  tento seznam a vyšší datové toky podpis z kamery chybí.
- **Offload aplikace.** OffShoot (dříve Hedge), Silverstack, ShotPut Pro a YoYotta řeší ověření kopie a ASC MHL. ASC MHL
  slouží jako chain of custody mezi kopiemi od placu po archiv (ascmhl), ale nemá externí ukotvení času: MHL
  s libovolným datem si kdokoli vyrobí znovu. Při hledání jsem nenašel, že by některá z těchto aplikací externí
  ukotvení nabízela.

Poptávka roste s deepfaky: důkaz o původu zdražuje zpochybnění záběrů. V Česku se už eIDAS razítka prodávají advokátům
jako důkaz o existenci webového obsahu, pro filmové záběry podobnou službu neznám.

## Co přesně dokazujeme

Offload Proof dokazuje existenci a integritu bajtů v čase, ne pravdivost obsahu. Tuhle hranici je potřeba říkat přesně
i v marketingu.

| Tvrzení | Dokážeme? | Čím |
|---|---|---|
| Soubor existoval nejpozději v čase T | Ano | eIDAS razítko a OpenTimestamps na Merkle kořen |
| Od T se nezměnil ani bajt | Ano | SHA-256 souboru a Merkle důkaz ke kořeni |
| Offload provedla konkrétní produkce nebo DIT | Ano, když je zapnutý podpis | Klíč produkce podepisuje manifest |
| Soubor vznikl v kameře, ne v počítači | Jen s podpisem z kamery | C2PA z kamery; Offload ho ověří a zapíše |
| Natáčeno v den D | Nepřímo | Jen „nejpozději v T“; mezi natáčením a offloadem je mezera |
| Záběr zachycuje skutečnost | Ne | Natáčení obrazovky s deepfakem projde |

### Model hrozeb

- Útočník upraví soubor po offloadu. SHA-256 nesedí s manifestem.
- Upraví soubor i manifest. Kořen nesedí s ukotveným kořenem.
- Vyrobí nový manifest se starším datem. Nemůže: nové ukotvení nese dnešní čas, ne starší.
- Vyrobí kolizi hashe. U SHA-256 prakticky nemožné. U xxHash možné, proto xxHash nikdy nenese důkaz.
- Kompromituje TSA nebo její certifikát. Druhé nezávislé ukotvení v Bitcoinu zůstává.
- Podvrhne soubor už na kartu před offloadem. Offload Proof to neodhalí; to umí jen podpis z kamery.

## Architektura

Na stroji DIT se spočítá a podepíše otisk offloadu a ven odchází jen ten. Obě ukotvení se vrací jako soubory `.ots`
a `.tsr` a ukládají se vedle dat na každý cílový disk, odkud je ověří kdokoli.

### Hashování a manifest

Každý soubor se při jednom čtení z karty zahashuje dvakrát: xxh128 pro rychlou verifikaci kopií a SHA-256 jako
kryptografický základ důkazu. Disk se kvůli tomu nečte navíc.

Proč SHA-256, ne BLAKE3 (oproti prvnímu návrhu): ASC MHL podporuje xxHash, MD5, SHA-1, SHA-256 a C4, BLAKE3 ne
(ascmhl). PostSignum TSA přijímá SHA-256 přímo. A moderní CPU (Intel a AMD s SHA-NI, Apple M přes ARMv8 Crypto)
počítají SHA-256 hardwarově, zhruba 1–2 GB/s na jádro (orientačně, je potřeba změřit). Soubory se hashují paralelně,
takže rychlá CFexpress karta by neměla být brzdou.

> **Poznámka z implementace (2026-11-19):** oficiální XSD ASC MHL v2 ani referenční ascmhl SHA-256 **nemají** (hashe
> c4, md5, sha1, xxh128, xxh3, xxh64). SHA-256 proto do ASC MHL nejde — nesel by ho žádný nástroj a soubor by neprošel
> schématem. Je v `offload_report.json` (`files[].sha256`) a v manifestu důkazu. Viz návrh MVP.

**Tok dat**

1. Blok dat z karty jde do zápisu na všechny cíle a zároveň do xxh128 i SHA-256.
2. Po zápisu Offload jako dosud zpětně čte cíle a porovná xxh128.
3. Teprve plně ověřené soubory vstupují do důkazu.

**Manifest má dvě vrstvy**

- ASC MHL generace ve složce `ascmhl/` na každém cíli, s oběma hashi (xxh128 i sha256). Díky tomu ji přečte jakýkoli
  nástroj v postprodukci. *(SHA-256 v MHL nejde — viz poznámka výše.)*
- `offload-proof.json` vedle ní, protože MHL nemá pole pro ukotvení a podpisy. Obsahuje: verzi formátu, ID offloadu,
  čas podle stroje (jen informativně), stroj, operátora, kartu (název, sériové číslo), kameru (model, sériové číslo,
  reel), seznam klipů (relativní cesta, velikost, sha256, xxh128, start timecode, délka, stav C2PA), sha256 souboru
  MHL, Merkle kořen, podpis a odkazy na `.ots` a `.tsr`.

**Kanonický zápis.** JSON se serializuje podle RFC 8785 (JCS: pevné pořadí klíčů, bez mezer), aby hash manifestu šel
kdykoli zreprodukovat. Každý hash nese název algoritmu (`sha256:…`), aby šlo později přidat jiný bez rozbití formátu.

**Proxy.** Každá proxy dostane záznam s vlastním sha256, parametry transkódu a `derived_from` = sha256 originálu. Proxy
vznikají až po offloadu, takže jdou do další dávky. Pozor: vazba proxy na originál je tvrzení Offloadu podložené
podpisem, ne matematický důkaz.

### Merkle strom a dávkování

Všechny soubory offloadu se složí do jednoho Merkle stromu a ukotví se jen jeho 32bajtový kořen. Jeden klip jde pak
ověřit bez zbytku offloadu.

Konstrukce podle vzoru Certificate Transparency (RFC 6962): listy a uzly mají různý prefix, aby nikdo nemohl vydávat
vnitřní uzel za list.

```
list_i = SHA256(0x00 ‖ sha256(soubor_i) ‖ velikost_i)        uzel = SHA256(0x01 ‖ L ‖ R)
```

Listy se řadí podle sha256, ne podle cesty. Přejmenování souboru nebo složky tak důkaz nerozbije; původní cesta zůstává
v manifestu.

**Inkluzní důkaz.** Pro jeden klip stačí cesta ke kořeni, zhruba log₂(n) hashů: pro 2 000 klipů je to 11 hashů, pár set
bajtů. Ověřovateli (advokát, pojišťovna) dáš jen ten klip a jeho cestu. Názvy ani hashe ostatních klipů neuvidí.

**Co se ukotvuje.** Kořen offloadu se spojí s hashem manifestu a podpisem do jednoho „otisku offloadu“ a ten se ukotví.

**Kdy ukotvovat**

- Výchozí: po každém offloadu. OpenTimestamps je zdarma; natáčecí den mívá jednotky až desítky offloadů, takže eIDAS
  razítek je málo.
- Dávkový režim pro velké objemy (multikamera, reality): otisky offloadů za hodinu nebo den tvoří druhý strom a ukotví
  se jen jeho kořen, tedy jedno razítko denně. Cenou je pozdější čas v důkazu.

### Ukotvení přes OpenTimestamps

OpenTimestamps (OTS) zapíše otisk offloadu do Bitcoinu zdarma a důkaz pak nezávisí na žádné firmě ani certifikátu.
Slabá místa jsou zpoždění v hodinách a hrubší čas.

**Jak to funguje (Wikipedia)**

1. **Stamp.** Klient k hashi přidá náhodný 128bitový nonce a znovu zahashuje, takže kalendář nevidí ani původní hash.
   Hodnotu pošle na více veřejných kalendářů, které ji zařadí do svého Merkle stromu a vrátí neúplný soubor `.ots`
   (pending).
2. **Bitcoin.** Kalendáře balí požadavky mnoha uživatelů do bitcoinových transakcí, které platí jejich provozovatelé.
   Proto je to pro uživatele zdarma.
3. **Upgrade.** Po potvrzení bloku (typicky hodiny) si klient stáhne cestu až k hlavičce bitcoinového bloku. Soubor
   `.ots` je pak samostatný důkaz a kalendář už není potřeba.
4. **Verify.** Ověřovatel přepočítá cestu z dat a porovná ji s Merkle kořenem v hlavičce bloku. Stačí pruned bitcoin
   node; ověření přes web opentimestamps.org je nejpohodlnější, ale nejméně bezpečné.

**Implementace.** Oficiální klienti existují v Pythonu, Javě a JavaScriptu, komunitní i v Dartu (pub.dev). Formát
`.ots` je malý a zdokumentovaný, dá se napsat i nativně.

**Pravidla pro Offload**

- Posílat vždy na aspoň 3 kalendáře; výpadek jednoho nevadí, protože každý vede k vlastní větvi důkazu.
- Offline: otisk se uloží do fronty v lokální databázi a odešle při připojení. Požadavek má jednotky kB, stačí hotspot
  z telefonu.
- Upgrade zkoušet každou hodinu první den, pak denně, dokud není důkaz kompletní. Kompletní `.ots` zapsat na všechny
  cílové disky.
- Přesnost: čas bitcoinového bloku je jen přibližný (řádově hodiny). OTS proto nedává přesný čas, dává neodvolatelnou
  horní hranici. Přesný čas nese eIDAS razítko.
- Právní váha: OTS je přípustný důkaz, ale bez zákonné domněnky. U soudu by ho nejspíš vysvětloval znalec.

### Kvalifikované časové razítko eIDAS

Kvalifikované razítko dává přesný čas a zákonnou domněnku správnosti v celé EU. Technicky je to jeden HTTPS požadavek na
offload a v Česku ho vydávají PostSignum (Česká pošta) a I.CA.

**Právní váha.** Podle čl. 41 odst. 2 nařízení eIDAS má kvalifikované razítko domněnku přesnosti data a času a integrity
dat, ke kterým se váže (text čl. 41). Důkazní břemeno se tím přesouvá na toho, kdo razítko zpochybňuje. Odstavec 1
navíc říká, že ani nekvalifikované razítko nelze odmítnout jen proto, že je elektronické.

**Jak se žádá (podle technického řešení PostSignum TSA)**

1. Offload sestaví RFC 3161 TimeStampReq: messageImprint = SHA-256 otisku offloadu, nonce, certReq = true, bez
   rozšíření.
2. Pošle ho přes HTTPS POST na URL TSA. Autentizace je jménem a heslem, nebo komerčním certifikátem PostSignum.
3. Dostane TimeStampResp (`.tsr`) podepsaný certifikátem TSA. Ověří ho, uloží na všechny cíle a k němu certifikační
   řetězec a stav revokace v době vydání (pro pozdější validaci).
4. Při výpadku primární adresy použije záložní (postsignum.eu); když nejde ani ta, opakuje s rostoucím odstupem. OTS
   mezitím důkaz drží.

**Podmínky PostSignum**

- Předplacené balíčky; razítka jdou čerpat 5 let od posledního nákupu a nový balíček prodlužuje i staré.
- Česká pošta garantuje platnost razítek nejméně 5 let; podpisové certifikáty TSA platí 6 let a mění se každý rok.
- Existuje bezplatné testovací TSA DEMO, není ale důvěryhodné a nemusí běžet stále. Na vývoj ideální.
- Přijímané hashe: SHA-1, SHA-256, SHA-384, SHA-512.
- Cenu za razítko je potřeba ověřit v aktuálním ceníku na postsignum.cz. Díky Merkle stromu jde o jedno razítko na
  offload nebo den, takže náklad na zákazníka bude zřejmě zanedbatelný.

**Kdo razítka platí**

- Vlastní účet zákazníka: zákazník si založí účet u TSA a zadá přístup do Offloadu. Pro tebe nulové náklady, pro
  zákazníka tření.
- Přes tvůj účet: razítka jsou součástí předplatného Offload Pro. Jednodušší pro zákazníka, ale je nutné ověřit, jestli
  podmínky TSA dovolují tuto formu odběru, a požadavky jdou přes tvůj server, aby se neprozradilo heslo.

### Podpis produkce

Razítko říká kdy, podpis říká kdo: „tento offload provedl DIT X pro produkci Y“. Ve výchozím stavu je podpis volitelný,
pro právní a pojistné použití doporučený.

- **Algoritmus:** ECDSA P-256. Ten umí hardwarově chránit Secure Enclave na Macu i TPM ve Windows, takže privátní klíč
  nikdy neopustí zařízení. Ed25519 by šel jen softwarově v klíčence.
- **Co se podepisuje:** kanonický `offload-proof.json`, tedy i Merkle kořen, metadata a hash MHL. Podpis vznikne před
  ukotvením, takže razítko pokrývá i jeho.
- **Identita:** veřejný klíč produkce zveřejněný na jejím webu nebo v Offload profilu, otisk klíče v PDF certifikátu.
  Pro firmy později volitelně kvalifikovaná elektronická pečeť eIDAS, která má vlastní domněnku původu.
- **Tým:** každý DIT má vlastní klíč, produkce ho podepíše svým klíčem (jednoduchý certifikát). Odchod člověka = záznam
  o odvolání klíče od data D, starší podpisy zůstávají platné díky razítku.
- **Ztráta zařízení:** nový klíč, odvolání starého. Nic se nepřerazítkovává, protože razítko dokazuje, že podpis vznikl
  před odvoláním.

### Podpisy z kamery (C2PA)

Kde kamera podepisuje sama, Offload její podpis zachová, ověří a zapíše. Spolu s ukotvením vznikne nejsilnější možný
řetězec: tuto kameru opustil tento soubor a nejpozději v čase T existoval beze změny.

- **Detekce:** při offloadu Offload zjistí, jestli soubor nese C2PA manifest. Dnes to platí hlavně pro MP4 ze Sony α
  a FX do 222 Mb/s s placenou licencí (RedShark News).
- **Ověření:** open-source knihovna c2pa-rs (Content Authenticity Initiative) umí manifest přečíst a ověřit podpis.
  Platnost podpisu je jedna věc, důvěra v podepisovatele druhá: k té je potřeba seznam důvěryhodných certifikátů
  výrobců.
- **Záznam:** do manifestu jde stav C2PA ke každému klipu: chybí / platný / neplatný, podepisovatel, čas z manifestu
  kamery.
- **Nikdy neměnit soubor.** Offload kopíruje bit po bitu, takže podpis kamery zůstává. Varování pro uživatele: některé
  aplikace zapisují metadata do originálu a tím rozbijí hash i podpis kamery.
- **Vztah k času:** čas v manifestu kamery podává kamera a může být špatně nastavený. Ukotvení dodá nezávislou horní
  hranici.

Sony u delších videí nabízí ořez se zachováním podpisu. Do budoucna to otevírá důkazy i pro výřezy, ne jen celé soubory.

### Dlouhodobá platnost

Důkaz musí vydržet tak dlouho jako archiv, tedy desítky let. Každé ukotvení stárne jinak, proto jsou dvě.

| Část | Co stárne | Opatření |
|---|---|---|
| eIDAS razítko | Certifikát TSA vyprší; PostSignum garantuje platnost min. 5 let | Před koncem platnosti přerazítkovat: nové razítko na hash starého `.tsr` a dat (postup podle RFC 4998, Evidence Record Syntax) |
| OpenTimestamps | Nevyprší; závisí na Bitcoinu a SHA-256 | Nic; při oslabení SHA-256 přerazítkovat novým algoritmem |
| SHA-256 | Dnes bez známých praktických útoků | Algoritmus je v manifestu pojmenovaný, dá se přidat nový |
| Podpis produkce | Klíč může uniknout nebo být odvolán | Razítko dokazuje, že podpis vznikl před odvoláním |

**Funkce „Obnovit důkazy“.** Offload projde archivní disky, najde důkazy, kterým končí platnost, a novým razítkem je
prodlouží. Na data nesahá, razítkuje jen soubory důkazů. To je dobrý důvod pro předplatné i po skončení natáčení.

**Kde důkazy leží.** Vždy u dat: na každém cílovém disku i LTO. Plus kopie u zákazníka nebo v Offload cloudu. Data bez
důkazu i důkaz bez dat jsou bezcenné.

### Nezávislý ověřovač

Ověřovač je zdarma, open-source a nepotřebuje Offload ani tvůj server. Důkaz, který jde ověřit jen tvým uzavřeným
programem, by protistrana snadno zpochybnila.

**Podoby**

- CLI (`offload-verify soubor.mxf --proof balicek/`) pro znalce a IT.
- Webová stránka, která počítá hash lokálně v prohlížeči, soubor se nikam neposílá. Pozor: WebCrypto neumí hashovat
  proudově, pro velké soubory je potřeba inkrementální SHA-256 ve WASM.

**Co kontroluje, v tomto pořadí**

1. Spočítá SHA-256 souboru a najde ho v manifestu nebo v inkluzním důkazu.
2. Ověří Merkle cestu ke kořeni offloadu.
3. Ověří podpis produkce nad manifestem a ukáže otisk klíče.
4. Ověří `.tsr`: podpis TSA, řetězec ke kvalifikované autoritě, platnost v čase razítka a shodu messageImprint
   s otiskem offloadu.
5. Ověří `.ots` proti hlavičce bitcoinového bloku (vlastní node, nebo hlavičky z více nezávislých zdrojů).
6. Volitelně ověří C2PA podpis kamery.

Výstup je čitelná zpráva, například: „Soubor A015C003.MXF (sha256 3f9a…) existoval nejpozději 14. 3. 2027 18:42:07 UTC
podle kvalifikovaného razítka PostSignum a nejpozději v bitcoinovém bloku č. … Offload podepsal klíč produkce …“ Ke
každému kroku zelená nebo červená a důvod.

## UX v Offloadu a PDF certifikát

Během offloadu uživatel nic navíc nedělá; Proof běží na pozadí a vidět je jen stav. Na konci si odnese PDF, které
pochopí i klient bez technických znalostí.

**Nastavení projektu**

- Offload Proof: zapnuto (výchozí).
- OpenTimestamps: zapnuto (zdarma).
- Kvalifikované razítko eIDAS: v Pro verzi.
- Podpis produkce: výběr klíče, nebo vypnuto.
- Ukotvení: po každém offloadu / dávkově.

**Stav u každého offloadu**

| Odznak | Stav | Co to znamená |
|---|---|---|
| Šedý | Čeká na síť | Otisk je ve frontě, nic se zatím neukotvilo |
| Modrý | Razítko eIDAS | Přesný čas je právně ukotvený, Bitcoin čeká |
| Oranžový | OTS pending | Kalendáře přijaly, čeká se na blok |
| Zelený | Kompletní | Obě ukotvení hotová, důkazy zapsané na všech cílech |
| Červený | Chyba | Např. soubor se po offloadu změnil; detail v logu |

**PDF certifikát offloadu**

- Hlavička: produkce, projekt, natáčecí den, DIT, stroj, karta, kamera.
- Tabulka klipů: název, start timecode, délka, velikost, zkrácený sha256, stav C2PA.
- Ukotvení: čas z eIDAS razítka (UTC i místní), TSA, číslo a čas bitcoinového bloku, otisk klíče produkce.
- QR kód na webový ověřovač a návod k ověření na jednu stránku.
- Věta nahoře: PDF je čitelné shrnutí, důkazem jsou soubory `.ots`, `.tsr` a manifest. Samotné PDF lze navíc opatřit
  eIDAS razítkem (PAdES).

**Důkazní balíček pro jeden klip.** Pravým klikem na klip → „Exportovat důkaz“: inkluzní důkaz, výřez manifestu, `.ots`,
`.tsr`, veřejný klíč a PDF. Právě tohle se posílá advokátovi nebo pojišťovně.

## Okrajové případy a selhání

Největší riziko není kryptografie, ale situace na placu: výpadek sítě, přerušený offload a aplikace, které sahají do
originálů.

| Situace | Co se stane | Řešení |
|---|---|---|
| Přerušený offload | Část souborů neověřená | Ukotvit jen plně ověřené soubory, manifest označí offload jako neúplný; dokončení = nová generace |
| Týdny offline (expedice) | Čas v důkazu bude až z doby připojení | Hotspot z telefonu stačí (kB); v PDF uvést, kdy byl otisk vytvořen a kdy ukotven |
| Aplikace zapíše metadata do originálu | Hash nesedí, důkaz pro soubor padne | Originály držet jen pro čtení; Offload při kontrole hlásí změnu červeně |
| Přejmenování souborů nebo složek | Nic | Důkaz stojí na obsahu, původní cesta je v manifestu |
| Export ze střihu, překódování | Nový soubor = nový hash | Důkaz platí jen pro originál; vazbu dokládá EDL a timecode, ne kryptografie |
| Stejný soubor dvakrát | Dva shodné listy | Povolit, v manifestu obě cesty |
| Špatně nastavené hodiny stroje nebo kamery | Čas v manifestu je špatně | Nevadí: důkazní čas je z TSA a Bitcoinu; velký rozdíl Offload ukáže jako varování |
| Kalendář OTS nedostupný | Jedna větev chybí | Posílat na ≥ 3 kalendáře |
| TSA nedostupná | eIDAS razítko se zpozdí | Záložní adresa, opakování s rostoucím odstupem; OTS mezitím drží |
| Karta se naformátuje dřív, než je důkaz kompletní | Nic | Důkaz se dokončí z cílových kopií, karta už není potřeba |

## Právní stránka

Obojí ukotvení je u českého soudu přípustný důkaz, ale jen eIDAS razítko má zákonnou domněnku správnosti. Před
marketingovými tvrzeními je potřeba konzultace s advokátem; tato kapitola není právní rada.

- **eIDAS čl. 41:** kvalifikované razítko má domněnku přesnosti data, času a integrity dat (odst. 2) a uznává se ve všech
  členských státech EU (odst. 3). Kdo ho zpochybňuje, musí své tvrzení prokázat.
- **Český civilní proces:** za důkaz může sloužit cokoli, čím lze zjistit stav věci (§ 125 o. s. ř.), a soud hodnotí
  důkazy podle své úvahy (§ 132). OTS je tedy přípustný, jeho váha ale závisí na tom, jak dobře ho někdo vysvětlí.
- **Co v produktu nikdy neříkat:** „dokazuje pravost záběru“, „dokazuje autorství“, „neprolomitelné u soudu“.
- **Co říkat:** „dokládá existenci a neporušenost dat nejpozději v uvedeném čase; kvalifikované razítko podle eIDAS“.
- **Ochrana dat:** ven odchází jen hash s náhodným nonce, ze kterého obsah zrekonstruovat nejde. V Bitcoinu není nic, co
  by produkci identifikovalo.
- **Odpovědnost:** v EULA vymezit, že Offload ručí za správný výpočet a uložení důkazů, ne za výsledek sporu ani za
  dostupnost TSA.

## Byznys

Proof je důvod, proč si koupit právě Offload, a ne další offload aplikaci. Základ dej zdarma kvůli marketingu, právně
silné části a archiv prodávej v předplatném.

| Segment | Co je pálí | Co jim Proof dá |
|---|---|---|
| Dokumentaristé, investigativa | Zpochybnění pravosti záběrů, ochrana zdrojů | Důkaz bez zveřejnění obsahu, kombinace s C2PA z kamery |
| Reklama a komerční produkce | Spory o dodání, termíny a práva | Doklad, co a kdy bylo natočeno a předáno |
| Svatby a eventy | „Nedodali jste“, „to není naše video“ | PDF certifikát pro klienta |
| Pojišťovny, znalci, právníci | Chain of custody u video důkazů | eIDAS razítko a nezávislý ověřovač |
| Archivy, TV, distributoři | Integrita na desítky let | Obnova důkazů, ASC MHL kompatibilita |

**Rozdělení do verzí**

- Zdarma v každé verzi: SHA-256 v manifestu, OpenTimestamps, ověřovač.
- Pro (předplatné): eIDAS razítka v ceně, PDF certifikáty, podpis produkce, důkazní balíčky.
- Archiv / Studio: obnova důkazů, týmové klíče, dávkový režim, kvalifikovaná pečeť.

**Positioning.** Ne „blockchain“ (to slovo v profi filmu spíš odrazuje), ale „offload s kvalifikovaným časovým
razítkem“. Bitcoin zmínit až v technickém popisu jako druhou nezávislou pojistku.

**Uvedení na trh**

- Pilot na vlastním dokumentu (Kanalizmus) a jedna případová studie.
- Ověřovač jako veřejná stránka: každé ověření je reklama na Offload.
- Oslovit DITy, kteří už pracují s ASC MHL, a advokáty specializované na autorské právo a média.

## Plán implementace

MVP s SHA-256, manifestem, Merkle kořenem, OpenTimestamps a CLI ověřovačem je zhruba 2–3 týdny práce. eIDAS a PDF
přijdou až ve v1. Odhady jsou hrubé, pro jednoho vývojáře, a závisí na tom, v čem je Offload postavený.

1. **Spike (2–3 dny).** SHA-256 ve stejném průchodu jako xxh128 a měření dopadu na rychlost offloadu s nejrychlejší
   kartou, kterou máš. Brána: zpomalení pod 5 %.
2. **MVP (2–3 týdny).** `offload-proof.json` s kanonickým zápisem, Merkle strom, OTS stamp a upgrade s frontou, stavový
   odznak, zápis `.ots` na cíle, CLI ověřovač. Brána: cizí člověk ověří klip jen s CLI a návodem.
3. **v1 (3–4 týdny).** RFC 3161 proti PostSignum DEMO a pak ostré TSA, ASC MHL se sha256, podpis produkce, PDF
   certifikát, důkazní balíček pro klip. Brána: pilot na skutečném natáčení a zpětná vazba od advokáta.
4. **v2 (4–6 týdnů).** Detekce a ověření C2PA, webový ověřovač (WASM), obnova důkazů, dávkový režim, týmové klíče.

**Testy povinné před vydáním**

- Změna jednoho bajtu v klipu, v manifestu i v `.tsr` musí ověřovač odhalit.
- Testovací vektory Merkle stromu (0, 1, 2, 3 a 2 001 listů) proti druhé, nezávisle napsané implementaci.
- Offload offline → připojení po 3 dnech → kompletní důkaz.
- Pád aplikace uprostřed offloadu a uprostřed ukotvení: žádný ukotvený otisk neúplného offloadu.

## Otevřené otázky

- [x] V čem je Offload postavený (jazyk, platformy)? — C# / .NET 10 (Windows) a Swift (Mac), společný formát
  [FORMATY.md](FORMATY.md); MVP nejdřív ve Windows.
- [ ] Kdo platí eIDAS razítka: vlastní účet zákazníka, nebo razítka v předplatném? Dovolují to podmínky PostSignum
  a I.CA?
- [ ] Jaká je aktuální cena razítka u PostSignum a I.CA?
- [ ] Ukotvovat po každém offloadu, nebo dávkově jako výchozí stav? *(MVP: po každém offloadu.)*
- [ ] Ověřovač jako open-source? (Doporučení: ano.)
- [ ] Finální název funkce: Offload Proof, nebo jinak?
- [ ] Konzultace s advokátem na formulace v marketingu a EULA.

## Zdroje

- Nařízení eIDAS, čl. 41
- PostSignum TSA – technické řešení
- ASC MHL – referenční implementace
- OpenTimestamps – Wikipedia
- OpenTimestamps pro Dart
- Sony Camera Authenticity pro video – RedShark News
- Google: Content Credentials pro video na Pixelu
- ProofSnap / Capture (Numbers Protocol)

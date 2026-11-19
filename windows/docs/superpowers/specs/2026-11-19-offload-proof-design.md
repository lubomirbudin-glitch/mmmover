# Offload Proof — MVP pro Windows (plán 11) — návrh

2026-11-19 · zadání uživatele: [docs/OFFLOAD-PROOF.md](../../../../docs/OFFLOAD-PROOF.md) („přidej do mmmoveru tuhle
funkci“, pak „udělej to“). Tento návrh popisuje **spike + MVP** ze zadání (fáze 1 a 2) ve Windows verzi a přesný formát
na disku. Mac převezme stejný formát později (úkol ve VYVOJ-MAC.md).

## Záměr

Ke každému offloadu vznikne důkaz, že tyto soubory existovaly přesně v tomto stavu nejpozději v čase T. Ven odchází jen
32bajtový hash (s náhodným nonce), nikdy obsah ani názvy. Důkaz jde ověřit bez mmMoveru: oficiálním klientem
OpenTimestamps (`ots verify`) a malým open-source skriptem v Pythonu. mmMover tím dostane funkci, kterou jiné offload
aplikace nemají.

## Cíle (MVP)

1. SHA-256 každého souboru při jediném čtení karty (vlastní vlákno hashe, karta se nečte navíc), v reportu
   `files[].sha256`. Spike změří dopad na rychlost (brána: zpomalení kopie pod 5 %).
2. Manifest důkazu `offload_proof.json` (kanonický JSON RFC 8785) na každém cíli, s Merkle kořenem podle RFC 6962.
3. OpenTimestamps: stamp na veřejné kalendáře (≥ 2 ze 4 musí přijmout), fronta offline, upgrade (každou hodinu první den,
   pak denně), neúplný a pak úplný `.ots` na všech cílech.
4. Ověřovač: `mmmover proof verify` (CLI) a nezávislý `shared/proof/verify_proof.py` (jen standardní knihovna Pythonu),
   ověření proti hlavičkám bitcoinových bloků ze dvou nezávislých zdrojů.
5. Stav důkazu na kartě úlohy (chip „Proof“), přepínač v Nastavení, CLI `--no-proof`, `proof status | upgrade | verify`.

## Mimo MVP (v1/v2 zadání)

eIDAS / RFC 3161, podpis produkce, PDF certifikát, důkazní balíček pro jeden klip (export inkluzního důkazu), C2PA,
webový ověřovač (WASM), obnova důkazů, dávkový režim, metadata kamery a klipů v manifestu, Mac verze.
Formát s nimi počítá: hash nese název algoritmu, manifest má `version`, `.tsr` a podpis přibudou jako další soubory vedle.

## Anti-cíle

- Proof nikdy neshodí ani nezdrží offload: chyba důkazu je řádek v logu a červený chip, „Safe to eject / Safe to format“
  se kvůli němu nemění.
- Žádné tvrzení o pravosti obsahu. Texty v UI říkají „existed unchanged no later than …“, nikdy „authentic“.
- Na kartu se nezapisuje nic; na cíle jen nové soubory v `_REPORT/` (výjimka: `.ots` se smí nahradit úplnějším — viz níže).
- ASC MHL se nemění (viz rozhodnutí 2).

## Rozhodnutí (moje, k potvrzení při čtení)

1. **Nejdřív Windows.** Tady jde Windows sestavit a otestovat; Swift ne. Formát je v FORMATY.md, Mac ho převezme.
2. **SHA-256 není v ASC MHL.** Oficiální XSD ASC MHL v2 (`ascmitc/mhl`, `xsd/ASCMHL.xsd`) a referenční ascmhl znají jen
   c4, md5, sha1, xxh128, xxh3, xxh64. `<sha256>` by neprošel schématem a žádný nástroj by ho nečetl. Zadání to
   předpokládalo podle popisu na PyPI. SHA-256 je v `offload_report.json` a v manifestu důkazu.
3. **Soubory v `_REPORT/`** (MHL ji už ignoruje i ve starších generacích, takže doplnění ani `ascmhl verify` nic nového
   nevidí): `offload_proof.json` (generace 1) / `offload_proof_NNNN.json` (doplnění, jako reporty) a vedle
   `<totéž>.ots`. Jméno s podtržítkem jako `offload_report.json` (zadání psalo `offload-proof.json`).
4. **Co se ukotvuje:** SHA-256 bajtů souboru manifestu. Manifest je zapsaný kanonicky (JCS), takže hash jde
   zreprodukovat, a `.ots` je standardní „detached timestamp“ téhož souboru — `ots verify offload_proof.json.ots` funguje
   oficiálním klientem. (Zadání: „kořen + hash manifestu + podpis“; podpis v MVP není a kořen je uvnitř manifestu.)
5. **Kdy se důkaz zakládá:** jakmile je záznam generace hotový — MHL zapsaná a ověřování skončilo (u ověření během proxy
   až po commitu ve fázi 2), tedy podle zadání jen ověřené soubory. Zrušená nebo selhaná kopie důkaz nedostane; navázání
   (resume) generaci dokončí a důkaz založí. Oprava („Copy again“) nový důkaz nezakládá (data jsou tatáž).
6. **Které soubory:** každý soubor generace se sha256, který report nevede jako selhaný (`IsFailed` = false: dobrá kopie
   na každém cíli). Ostatní jdou do `excluded` a `complete` = false. Bez jediného souboru se důkaz nezakládá.
7. **Kalendáře:** stejné agregátory jako oficiální klient: `https://a.pool.opentimestamps.org`,
   `https://b.pool.opentimestamps.org`, `https://a.pool.eternitywall.com`, `https://ots.btc.catallaxy.com`. Upgrade jen
   z kalendářů na seznamu povolených (`https://*.calendar.opentimestamps.org`, `https://*.calendar.eternitywall.com`,
   `https://*.calendar.catallaxy.com`), jako oficiální klient.
8. **Hlavičky bloků:** `https://blockstream.info/api` a `https://mempool.space/api`; obě musí vrátit stejnou hlavičku.
   Jen jeden zdroj dostupný = ověřeno s varováním; žádný = „not checked“.
9. **Nastavení:** sekce profilu `proof` (`{"enabled": true}`, výchozí zapnuto, jako zadání). Vypnuto = SHA-256 se
   nepočítá vůbec (nulový dopad na rychlost).
10. **Fronta:** `%APPDATA%\mmMover\proof\<id>.json` + `<id>.ots`. Upgrade a dopsání na disky dělá aplikace na pozadí,
    CLI po své úloze jednou (nejvýš 20 s) a příkazem `mmmover proof upgrade`.

## Formát na disku (smlouva; zapíše se do FORMATY.md)

### `files[].sha256` v `offload_report.json`

64 malých hex číslic SHA-256 souboru z karty; chybí, když důkaz byl vypnutý nebo soubor nešel přečíst.
`hashAlgorithms` vyjmenuje i `"sha256"` (`["xxh64", "sha256"]`, `["xxh64", "md5", "sha256"]`); `hashAlgorithm` zůstává
`xxh64`. Mac klíč i hodnotu ignoruje (`HashKinds.from(names:)` hledá jen md5). Blokový manifest
(`offload-manifest.jsonl`) nese `sha256` vedle `xxh64`, aby navázání po pádu znalo hash souborů, které už nečte.

### Manifest `_REPORT/offload_proof.json`

UTF-8 bez BOM, bez koncového řádku, **přesně** kanonická serializace RFC 8785 (klíče seřazené podle UTF-16 jednotek,
bez mezer; v manifestu jsou jen řetězce, celá čísla, `true/false` a pole/objekty). Klíče (verze 1):

| Klíč | Typ | Obsah |
|---|---|---|
| `format` | string | `"mmmover-proof"` |
| `version` | int | `1` |
| `id` | string | UUID malými písmeny s pomlčkami |
| `created` | string | čas stroje `yyyy-MM-ddTHH:mm:ssZ` (UTC) — jen informativně, důkazní čas je z ukotvení |
| `tool` | object | `name` `"mmMover"`, `version` (`OffloadVersion.String`), `platform` `"windows"` |
| `machine` | string | jméno počítače |
| `card` | object | `name`, `date` (`yyyy-MM-dd` složky dne), `source` (jako report), `generation` (int, 1 = celá kopie), `project`? (chybí bez projektu) |
| `complete` | bool | každý soubor generace je ve `files` |
| `files` | array | seřazené podle `path` (ordinálně): `path` (relativní, `/`), `size` (int), `sha256` `"sha256:<64 hex>"`, `xxh64` `"xxh64:<16 hex>"`, `xxh128`? `"xxh128:<32 hex>"` |
| `excluded` | array? | jen když `complete` = false: `path`, `reason` (`"source"` karta nedala soubor, `"destination"` není dobrá kopie na každém cíli, `"hash"` chybí sha256) |
| `merkle` | object | `scheme` `"rfc6962-sha256"`, `count` (int = počet `files`), `root` `"sha256:<64 hex>"` |
| `mhl` | array | ke každému cíli, kde generace ASC MHL existuje: `destination` (int, 1…), `path` (`ascmhl/<soubor>.mhl`), `sha256` `"sha256:<hex>"` |

**Merkle strom (RFC 6962 §2.1):** data listu = 32 bajtů SHA-256 souboru ‖ velikost jako 8 bajtů big-endian; list =
SHA-256(0x00 ‖ data), uzel = SHA-256(0x01 ‖ L ‖ R), MTH pro n > 1 dělí na k = největší mocnina dvou < n; prázdný strom
SHA-256(""). Listy seřazené podle SHA-256 souboru (bajtově), pak podle velikosti; stejný soubor dvakrát = dva listy.
Kontrola správnosti: kořeny pro testovací vstupy Certificate Transparency (1–8 listů, `6e340b9c…`, …, `5dc9da79…`)
a vektory z nezávislé implementace v Pythonu (0, 1, 2, 3, 2001 listů) v `shared/proof/vectors.json`.

### `_REPORT/offload_proof.json.ots`

Standardní soubor OpenTimestamps (DetachedTimestampFile, major verze 1, file hash op SHA-256 přes bajty manifestu).
Stamp: digest manifestu → `append(16 náhodných bajtů)` → `sha256` → commitment, ten jde POST `<kalendář>/digest`
(tělo 32 bajtů, `Accept: application/vnd.opentimestamps.v1`); odpovědi (strom od commitmentu) se sloučí do jednoho
stromu. Upgrade: ke každé `PendingAttestation(uri)` GET `<uri>/timestamp/<hex commitment>` (200 = sloučit, 404 = ještě
ne). Serializace jako referenční `python-opentimestamps` (atestace a operace seřazené, `0xff` před každou položkou kromě
poslední, atestace `0x00` + 8bajtový tag + varbytes payload; tagy Pending `83dfe30d2ef90c8e`, Bitcoin
`0588960d73d71901`; LEB128 varuint).

**Jediný soubor v záloze, který se smí nahradit** (vedle seznamů hashů a řetězu ASC MHL): `.ots` se nahradí úplnějším,
jen když nový míří na stejný digest a obsahuje každou atestaci starého (upgrade jen přidává). Jinak se nechá a zapíše
se do logu. Zapisuje se jen do složky karty, kde manifest se stejným SHA-256 už leží.

## Fronta a stavy

Záznam `%APPDATA%\mmMover\proof\<id>.json` (+ `<id>.ots`, poslední známý strom): `id`, `created`, `manifest` (jméno
souboru), `digest` (hex), `cardName`, `date`, `generation`, `cardPaths[]`, `volumeSerials[]`, `state`, `stampedAt`?,
`nextCheck`?, `tries`, `lastError`?, `bitcoin`? {`height`, `time`}, `written[]` (per cíl `"none" | "pending" |
"complete"`). Zápisy pod pojmenovaným mutexem `Local\mmMover-proof-store`; síť nikdy pod ním.

| Stav | Chip na kartě úlohy | Kdy dál |
|---|---|---|
| `queued` | šedý „Proof: waiting for network“ | stamp znovu za 1, 2, 5, 10, 30, pak každých 60 min |
| `pending` | šedý „Proof: anchoring — Bitcoin confirms in a few hours“ | upgrade každou hodinu prvních 24 h od stampu, pak denně |
| `complete` | zelený „Proof: anchored (block N)“; když ještě není na všech discích, oranžový „Proof: anchored — on 1 of 2 disks“ | zápis na chybějící disky při každém běhu služby (10 min) a po připojení disku |
| `failed` | červený „Proof: not created“ + důvod v tooltipu | nic (manifest se nezapsal) |

## Ověřovač

`mmmover proof verify <soubor | složka karty> [--offline]`:

1. SHA-256 souboru; najde složku karty (nahoru k `_REPORT/offload_proof*.json`) a záznam se stejným `sha256` a `size`
   (jiná cesta = přejmenováno, jen poznámka).
2. Přepočítá Merkle kořen ze `files` a porovná s `merkle.root` a `count`; zkontroluje, že manifest je kanonický JCS.
3. `.ots`: digest v souboru = SHA-256 manifestu; projde strom; Bitcoin atestace ověří proti hlavičce bloku (merkle root
   z bajtů 36–68 = zpráva v uzlu, čas = bajty 68–72 LE) ze dvou zdrojů; hash hlavičky (dvojitý SHA-256, obráceně) musí
   sedět s hashem bloku. `--offline` jen vypíše, co v `.ots` je.
4. Výstup (anglicky), např.:

```
File:      A001C003.MXF
SHA-256:   3f9a…c1  — matches offload_proof.json (card A001, 2026-11-19, 214 files, Merkle root OK)
Anchor:    Bitcoin block 912345, 2026-11-19 23:41:07 UTC (blockstream.info and mempool.space agree)
RESULT:    OK — this file existed unchanged no later than 2026-11-19 23:41:07 UTC.
```

Návratový kód 0 = OK, 1 = FAILED (nesedí hash, kořen, digest, poškozený `.ots`), 2 = NOT YET (jen pending / neověřeno
offline). Složka karty: přepočítá každý soubor všech manifestů a vypíše souhrn.

`shared/proof/verify_proof.py` dělá totéž bez .NET (Python ≥ 3.8, jen standardní knihovna) a generuje
`shared/proof/vectors.json` (Merkle, JCS), proti kterým testuje C#.

## Rychlost (spike)

SHA-256 dostane vlastní `SourceHasher` (vlákno jako MD5), karta se čte jednou. Zdrží kopii, jen když je SHA-256
pomalejší než čtení karty. `mmmover bench --hash sha256` změří propustnost; výsledek a brána (< 5 %) se zapíšou do
VYVOJ-WINDOWS.md. Zpětné čtení cílů SHA-256 nepočítá (porovnává xxh64, MD5 jako dosud).

## Povinné testy (ze zadání)

- Změna jednoho bajtu v klipu, v manifestu i v `.ots` → ověřovač FAILED.
- Merkle 0, 1, 2, 3 a 2001 listů proti vektorům z Pythonu; CT vektory 1–8.
- Offline → po připojení (simulované hodiny, 3 dny) → úplný důkaz na discích.
- Pád uprostřed offloadu (navázání) a uprostřed ukotvení: neukotví se nic z neúplné generace; fronta po restartu
  pokračuje.

## Co zbývá na implementátorovi

Rozmístění tříd ve složce `Offload.Core/Proof/`, přesné texty chybových řádků (anglicky, podle
`docs/ui-text-glossary.md`), tvar UI v Nastavení (podle existujících přepínačů).

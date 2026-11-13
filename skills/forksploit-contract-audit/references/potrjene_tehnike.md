# Rastoča knjižnica potrjenih tehnik

Ta datoteka je **dejanski, berljiv zapisnik**, ne mehanizem za "učenje modela" —
model se s pisanjem sem ne spremeni. Namen je, da naslednja seja (človek ali agent)
prebere, kaj je bilo v preteklosti DEJANSKO uspešno preverjeno (FAZA 8 v
`../SKILL.md` je bila dosežena), in se ne začne iz nič.

**Pravilo vnosa**: nov vnos se dodaja SAMO po tem, ko je FAZA 8 (preverjanje
saldov PRED/PO na pravem vozlišču) dejansko potrdila uspeh. Nikoli ne dodajaj
vnosa na podlagi "forge script je rekel SUCCESSFUL" ali "ForkSploit je rekel
Found vulnerabilities" samih po sebi.

## Format vnosa

```
### <DATUM ISO> — <bug_type> na <veriga>

- **Tarča**: <naslov pogodbe>
- **Recovery wallet**: <naslov>
- **Znesek**: <koliko je dejansko prispelo, potrjeno FAZO 8>
- **Kaj je delovalo**: <kratek povzetek korakov/posebnosti te tarče>
- **Posebnosti/presenečenja**: <karkoli nestandardno, kar bi koristilo naslednjič>
```

---

<!-- Vnosi se dodajajo spodaj, najnovejši na vrhu. -->

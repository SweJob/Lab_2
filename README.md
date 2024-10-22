# Laboration

As a  part of the education "IT Säkerhetstestare" at "IT-Högskolan"  we got this assigment in the "programmering för pentestare" class:

---
## Krypteringsverktyg
Inlämning ska ske som ett Github repo

### Skapa ett verktyg som kan:
- Generera och spara en krypteringsnyckel.
- Kryptera en fil med hjälp av en symmetrisk nyckel (filnamn som argument).
- en krypterad fil med rätt nyckel (filnamn som argument).

- Använd cryptography-biblioteket (Fernet rekommenderas)
- Använd argparse-biblioteket för att ta argument


### Krav:
- Nyckelgenerering:
    - Skapa ett separat skript (ex: generate_key.py) som genererar en symmetrisk nyckel och sparar den i en fil.

- Kryptering och Dekryptering:  
    - Implementera ett andra skript (ex crypto_tool.py) som använder argparse för att hantera kommandoradsalternativ och utföra följande funktioner:
    - Kryptera en fil med en befintlig nyckel.
    - Dekryptera en krypterad fil och återställa originalet.

### Förslag på extrafunktioner (frivilligt):

- Implementera felhantering för fil om den saknas
- Lägg till funktionalitet för att skapa en lösenordsbaserad nyckel med hjälp av PBKDF2.

### Avancerat alternativ:
- Skapa ett script som krypterar shellcode och sedan genererar en nyckel och krypterad shellcode som char arrays för användning i C.  
Nyckeln ska sedan kunna användas för att dekryptera shellcoden i ett c-program  
(vi kommer göra detta i en framtida kurs)
---

## Documentation
The separate tools have a more detalied documentation here:  
- [keygenerator.py](keygenerator.md) The tool to generate keys (gernates symmetric key and an assymetric keypair)
- [crypto_tool.py](crypto_tool.md) The tool to en-/decrypt files. Can use the above created keyfiles or use a password to en-/decrypt with
- [sc_obfuscator.py](sc_obfuscator.md) The tool to obfuscate a shellcode and store as a file of hexvalues to be imported in a c-program.
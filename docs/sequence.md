![Logo](images/digg.png)

# Auktorisationsflöden - Once Only Technical System, SDG

## Auktorisationsflöden
* Bevishämtning, svenskt onlinfeförarande hämtar bevis frän annat medlemsland
```mermaid
flowchart LR
    OLF(Onlineförfarande)-->AT(SDG Auktorisationstjänst)
    OLF-->BF(Bevisförmedling)
    BF-->OSE(OOTS-nod SE)
    OSE-->OMS(OOTS-nod MS)
```

* Bevisförmedling, utländskt onlinteförfarande hämtar bevis fråån Sverige
```mermaid
flowchart LR
    FGT(Förhandsgranskningstjänsten)-->AT(SDG Auktorisationstjänst)
    AT-->LT(Legitimeringstjänst)
    FGT-->BT(Bevistjänst)
```

### Auktorisationsflöde vid bevishämtning
#### Beskrivning

När en användare i ett svenskt onlineförfarande vill hämta ett digitalt bevis från ett annat medlemsland.
Ett svenskt onlineförfarand begär ett åtkomstintyg för att kunna anropa den svenska bevisförmedlingstjänsten för 
att hämta ett bevis via OOTS.

#### Flödesbeskrivning

* Använderaren vill hämta ett bevis från annat medlemsland
* E-tjänsten skickar en signerad begäran om åtkomst till SDG Auktorisationstjänst
* Auktorisationstjänsten validerar begäran och kontrollerar att e-tjänsten tillhör en behörig myndighet
* Auktorisationstjänsten ställer ut ett åtkomstintyg till e-tjänsten
* E-tjänsten anropar Bevisförmedlingstjänsten och bifogar åtkomstintyget
* Vidareföremdlingstjänsten validerar att åtkomstintyget är signerat av betrodd auktorisationstjänst
* Vidareförmedlingstjänsten gör en bevisbegäran via OOTS SE


#### Detaljerat flöde

```mermaid
sequenceDiagram
autonumber
box Klient
participant W as Webläsare
participant OF as e-tjänst
end
box SDG auktorisation
participant AT as Auktorisationstjänst
end
participant BT as Bevisförmedlingstjänsten 
participant OTSE as OOTS SE
participant OTMS as OOTS MS
participant MSOF as Förhandsgranskning MS
W->>OF: Begär bevis
Note right of OF: Authentisering & auktorisation
OF->>AT: Access Token Request
AT-->>OF: Access Token Grant (accesstoken)
Opt Token expired
OF->>AT: Access Token Request(refresh token)
AT-->OF: Access Token Grant (accesstoken)
end
OF->>BT: API request (accesstoken)
BT->>BT: Validate Access Token
BT->>OT: Bevisbegäran
OT->>BT: Svar på bevisbegäran
BT-->>OF: Svar på bevisbegäran
OF->>W: Omdirigering till Förhandsgranskning MS
W-->>MSOF: omdiringering
```
*Diagram 1: Sekvensdiagram över auktorisationsflödet vid bevishämtning*

### Auktorisationsflöde vid bevisförmedling

#### Beskrivning

När en användare via ett utländskt onlineförfarande vill hämta ett digitalt bevis från Sverige.
Användaren blir omdirigerad till den svenska förhandsgranskningstjänsten som autentiserar användaren och begär ett åtkomstintyg för att anropa bevistjänsten som ska tillhandahålla beviset.

#### Flödesbeskrivning
* TBD!

#### Detaljerat flöde

```mermaid
sequenceDiagram
autonumber
box Klient
participant W as Webläsare
participant F as Förhandsgranskning
end
box SDG Identitet och auktorisation
participant AT as Auktorisationstjänst
participant LT as Legitimeringstjänst
end
box Producent
participant BT as Bevistjänst
end
Note right of F: Autentisering
W->>F: Logga in
F->>AT: Auth request
Opt Autentisera användare
AT->>AT: Autentisera Användare
W-->LT: Flöde ej inritat i detta diagram
end
AT-->>W: Access Token Grant (code)
W->>F: Access Token Grant (code)
F->>AT: Id Token Request (code)
AT-->>F: Id Token Response (idtoken, accesstoken, refreshtoken)
Note right of F: User info
F->>AT: User Info Request (accesstoken)
AT-->>F: User Info Response (userinfo)
Note right of F: Auktorisation
F->>AT: Access Token Request (code/accesstoken)
AT-->>F: Access Token Grant (accesstoken)
Opt Token expired
F->>AT: Access Token Request(refresh token)
AT-->F: Access Token Grant (accesstoken)
end
F->>BT: API request (accesstoken)
BT->>BT: Validate Access Token
BT-->>F: API response (protected resource)
```
*Diagram 2: Sekvensdiagram över auktorisationsflödet vid bevisförmedling*


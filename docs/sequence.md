![Logo](images/digg.png)
# SDG Auhtorizaion Sekvens diagram
## Bevishämtning
När en användare i ett svenskt onlineförfarande vill hämta ett digitalt bevis från ett annat eu medlemsland.
Det svenska online förfarandet begär ett åtkomstintyg för att kunna anropa den svenska vidareförmedlingstjänsten för 
att hämta ett bevis via OOTS.
### Sekvensdiagram
*TBD!

## Bevisförmedling
När en användare via ett utländskt onlineförfarande vill hämta ett digitalt bevis från Sverige.
Användaren blir omdirigerad till den svenska förhandsgranskningstjänsten som autentiserar användaren och begär ett 
åtkomstintyg för att anropa bevistjänsten som ska tillhandahålla beviset.
### Sekvensdiagram
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


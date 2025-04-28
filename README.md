![Logo](docs/images/digg.png)

# SDG OAuth2 och OpenID Connect-exempel

I katalogen `samples` tillhandahåller vi ett antal olika exempelapplikationer som illustrerar 
hur man hanterar **OAuth2** och **OpenID Connect** inom det svenska **OOTS-systemet** 
(Once Only Technical System - Single Digital Gateway).

## Applikationerna är:

- [Svenskt onlineförfarande](samples/directaccessclient/README.md)
  Bevishämtning, svenskt onlineförfarande hämtar bevis från annat medlemsland. 
  Applikationen gör det via Uppslag och bevishämtningtjänsten. För detta krävs auktorisering, 
  och applikationen hämtar åstkomstintyg från **auktorisationstjänsten**

- [Bevistjänst](samples/bevistjanst/README.md)
  Ett exempel på en API-tjänst som tar emot och använder **åtkomstintyg** som utfärdats av auktorisationstjänsten på begäran av Förhandsgranskningstjänsten.

- [Förhandsgranskningstjänst](samples/forhandsgranskning//README.md)
  Förhandsgranskningsapplikationen som användaren loggar in i (med hjälp av OpenID Connect). Applikationen gör därefter anrop till olika **bevistjänster**. 
  För detta krävs auktorisering, och applikationen hämtar åstkomstintyg från **auktorisationstjänsten**

## Sekvensdiagram:

- **Användningsfall**  
  [Sekvensdiagram](../docs/sequence.md) för bevishämtning som beskriver hur man hämtar ett **åtkomstintyg** från auktorisationstjänsten.
  
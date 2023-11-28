# Documentatie voor Authenticatie applicatie

Deze applicatie is een voorbeeld van eeen gebruikserautheticatiesysteem gebouwd met NodeJS, Express MongoDB en andere modules. Het biedt functionaliteit voor registratie, inloggen, accountverificatie via e-mail en sessiebeheer.

# Functionaliteit

1.  Registratie: `/register` route om nieuwe gebruikers toe te voegen aan de database na validatie.
2.  Inloggen: `/login` route om gebruikers in te loggen met controle op gebruikersnaam/e-mail en wachtwoord. Na meerdere mislukte inlogpogingen worden de accounts geblokkeerd.
3.  Verify: `/verify` route om accounts te verifieren via een gegenereerde token die per e-mail wordt verzonden.
4.  Sessiebeheer: gebruik van express-session voor sessiebeheer een authenticatie.

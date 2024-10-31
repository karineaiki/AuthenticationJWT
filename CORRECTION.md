# Qu'est-ce qui permet de garder en mémoire le JWT reçu lors de la connexion : LocalStorage ou Cookies ?

- Nous pouvons voir que le token a été stocké dans le front dans le local storage et non dans les cookies via le fichier auth.interceptor.ts

# Comment le token est fourni lors des appels d'API ?

- quand une requête d'authentification est envoyée le backend réceptionne les informations et crée le token. Elle est envoyée dans la réponse http.

# Qu'est-ce qui empêche d'accéder aux pages, si l'on n'a pas le rôle correspondant ?

```
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(csrf -> csrf.disable())
                .cors(Customizer.withDefaults())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/auth/**").permitAll()
                        .anyRequest().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
                .build();
    }
```

Ce bloc de code en backend nous permet de gérer les authentifications. anyRequest().authenticated() nous dit qu'il faut être authentifié pour être authorisé à accéder au site.

``
    @GetMapping("/user")
    @PreAuthorize("hasAuthority('SCOPE_ROLE_USER')")
    public String userAccess() {
        return "User access";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasAuthority('SCOPE_ROLE_ADMIN')")
    public String adminAccess() {
        return "Admin access";
    }
``

ce code nous permet de comprendre qui accède à quoi.


```
public String generateToken(Authentication auth) {
        // crée l'en-tête
        JwsHeader header = JwsHeader.with(() -> "HS256").build();

        String scope = auth.getAuthorities().stream()
                .map((authority) -> authority.getAuthority())
                .collect(Collectors.joining(" ")); // ex: "ROLE_USER ROLE_ADMIN"

        Instant now = Instant.now();
        JwtClaimsSet payload = JwtClaimsSet.builder()
                .issuer("self")
                // a été créé à l'instant
                .issuedAt(now)
                // expire dans une heure
                .expiresAt(now.plus(1, ChronoUnit.HOURS))
                // s'adresse à l'utilisateur connecté : ici renvoie son email
                .subject(auth.getName())
                // scope: correspond aux rôles de l'utilisateur
                .claim("scope", scope)
                .build();

        // la signature sera générée par la méthode encode du JwtEncoder
        return this.encoder.encode(JwtEncoderParameters.from(header, payload)).getTokenValue();
    }
```

Ce code nous explique que le rôle est stocké dans le token créé pour passer l'information au front.
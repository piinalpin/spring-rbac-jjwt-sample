# Role Based Access Control with jjwt-api and Spring Boot 2.7.0

I wrote this article in hopes of helping people to implement how JWT works on Spring Boot 2.7.0 because some class is **deprecated** by Spring Security 5.7.0-M2 like `WebSecurityConfigurerAdapter`. So, we should move towards a component-based security configuration.

## Project Setup and Dependency

Create project in [Spring Initializr](https://start.spring.io/). And add the dependency i.e :

* Spring Web
* Spring Data JPA
* H2 Database
* Lombok
* Spring Security
* JSON Web Token

Which will look like something like this on our `pom.xml`

```xml
<dependencies>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-data-jpa</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
        <groupId>io.jsonwebtoken</groupId>
        <artifactId>jjwt-api</artifactId>
        <version>0.11.5</version>
    </dependency>
    <dependency>
        <groupId>io.jsonwebtoken</groupId>
        <artifactId>jjwt-impl</artifactId>
        <version>0.11.5</version>
        <scope>runtime</scope>
    </dependency>
    <dependency>
        <groupId>io.jsonwebtoken</groupId>
        <artifactId>jjwt-jackson</artifactId>
        <version>0.11.1</version>
        <scope>runtime</scope>
    </dependency>		
    <dependency>
        <groupId>org.projectlombok</groupId>
        <artifactId>lombok</artifactId>
        <version>1.18.24</version>
        <scope>provided</scope>
    </dependency>		
    

    <dependency>
        <groupId>com.h2database</groupId>
        <artifactId>h2</artifactId>
        <scope>runtime</scope>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-test</artifactId>
        <scope>test</scope>
    </dependency>
    <dependency>
        <groupId>org.springframework.security</groupId>
        <artifactId>spring-security-test</artifactId>
        <scope>test</scope>
    </dependency>
</dependencies>
```

And add variables on `application.properties`

```sh
jwt.token.validity=18000
jwt.signing.key=lLz0wjFXoLhdj4xfGX4gc192O29JBRkcSF9DmPkyYVOn6gCAUa
jwt.authorities.key=roles

spring.datasource.url=jdbc:h2:mem:db
spring.datasource.driverClassName=org.h2.Driver
spring.datasource.username=sa
spring.datasource.password=password
spring.jpa.database-platform=org.hibernate.dialect.H2Dialect
spring.h2.console.enabled=true

spring.main.allow-bean-definition-overriding=true
spring.main.allow-circular-references=true
```
## Implementation

**Request Layer**

`LoginRequest`

```java
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LoginRequest {

    private String username;

    private String password;
    
}
```
`LoginResponse`

```java
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LoginResponse {

    private String token;
    
}
```
`PingResponse`

```java
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PingResponse {

    private String message;
    
}
```

**User Model**

User model has one to many relation to user role model and assign into `GrantedAuthority`.
```java
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "M_USER")
@ToString(exclude = {"authorities"})
public class User implements UserDetails {

    private static final long serialVersionUID = -5851955212775343458L;

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @Column(name = "username", nullable = false)
    private String username;

    @JsonIgnore
    @Column(name = "password", nullable = false)
    private String password;

    @Column(name = "full_name", nullable = false)
    private String fullName;

    @Column(name = "business_title", nullable = false)
    private String businessTitle;

    @JsonIgnoreProperties(value = {"user"})
    @OneToMany(fetch = FetchType.EAGER, mappedBy = "user", cascade = CascadeType.ALL)
    private List<UserRole> authorities;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities.stream().collect(Collectors.toList());
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
    
}
```

**User Role Model**

Relation using fetch type `EAGER`
```java
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "M_USER_ROLE")
public class UserRole implements GrantedAuthority {
    
    private static final long serialVersionUID = -896978443561403016L;

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @Column(name = "role", nullable = false)
    private String role;

    @ManyToOne(fetch = FetchType.EAGER)
    private User user;

    @Override
    public String getAuthority() {
        return role;
    }
    
}
```
**Repository and Service Layer**

`UserRepository`

```java
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    
    User findByUsername(String username);

}
```
`UserRoleRepository`

```java
@Repository
public interface UserRoleRepository extends JpaRepository<UserRole, Long> {

    UserRole findByUserIdAndRole(Long userId, String role);
    
}
```
`UserService` implement `UserDetailsService` to override `oadByUsername` method

```java
@Service(value = "userDetailsService")
public class UserService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username);

        if (user == null) {
            throw new UsernameNotFoundException("Invalid username or password");
        }
        
        return user;
    }
    
}
```

**Token Provider**

The token utility as componen which can be used for generate token and validate token.

```java
@Component
public class TokenProvider implements Serializable {

    private static final long serialVersionUID = -1403857064104614481L;

    @Value("${jwt.token.validity:18000}")
    private long tokenExpires;

    @Value("${jwt.signing.key:lLz0wjFXoLhdj4xfGX4gc192O29JBRkcSF9DmPkyYVOn6gCAUa}")
    private String signingKey;

    @Value("${jwt.authorities.key:roles}")
    private String authoritiesKey;

    private Key key;

    @PostConstruct
    public void init() {
        final byte[] signingKeyBytes = Base64.getDecoder().decode(signingKey);
        key = new SecretKeySpec(signingKeyBytes, 0, signingKeyBytes.length, SignatureAlgorithm.HS256.getJcaName());
    }


    public String getUsername(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    public Date getExpirationDate(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    private <T> T getClaimFromToken(String token, Function<Claims, T> claimResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimResolver.apply(claims);
    }

    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private boolean isExpired(String token) {
        final Date expirationDate = getExpirationDate(token);
        return expirationDate.before(new Date());
    }

    public String generateToken(Authentication authentication) {
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));
        
        return Jwts.builder()
                .setSubject(authentication.getName())
                .claim(authoritiesKey, authorities)
                .signWith(key)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + tokenExpires))
                .compact();
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = getUsername(token);
        return (username.equals(userDetails.getUsername()) && !isExpired(token));
    }

    public Authentication getAuthenticationToken(final String token, final Authentication authentication, final UserDetails userDetails) {
        final JwtParser jwtParser = Jwts.parserBuilder()
                .setSigningKey(key)
                .build();
        
        final Jws<Claims> claimsJws = jwtParser.parseClaimsJws(token);

        final Claims claims = claimsJws.getBody();

        final Collection<? extends GrantedAuthority> authorities = Arrays.stream(claims.get(authoritiesKey).toString().split(","))
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
        
        return new UsernamePasswordAuthenticationToken(userDetails, "", authorities);
    }
    
}
```

**Unauthorized Entry Point**

Used for error handling when unauthorized client.

```java
@Component
public class UnauthorizedEntryPoint implements AuthenticationEntryPoint, Serializable {

    private static final long serialVersionUID = -8970718410437077606L;

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
            org.springframework.security.core.AuthenticationException authException) throws IOException {
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
    }
}
```

**JWT Authentication Filter**

To filter request create custom filter for web security usage.

```java
@Slf4j
public class JwtAuthenticationFilter extends GenericFilterBean {

    
    private final UserDetailsService userDetailsService;
    private final TokenProvider jwtTokenUtil;

    public JwtAuthenticationFilter(TokenProvider jwtTokenUtil, UserDetailsService userDetailsService) {
        this.jwtTokenUtil = jwtTokenUtil;
        this.userDetailsService = userDetailsService;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        String authorization = httpServletRequest.getHeader(HttpHeaders.AUTHORIZATION);
        String token = null;
        String username = null;
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authorization != null && authorization.startsWith(Constant.General.BEARER)) {
            token = authorization.replace(Constant.General.BEARER, "");

            try {
                username = jwtTokenUtil.getUsername(token);
            } catch (IllegalArgumentException e) {
                log.error("An error occured during getting username from token", e);
            } catch (ExpiredJwtException e) {
                log.error("Token is expired", e);
            } catch (SignatureException e) {
                log.error("Authentication Failed. Username or Password not valid.");
            }
        }

        if (username != null && authentication == null) {
            User user = (User) userDetailsService.loadUserByUsername(username);

            if (jwtTokenUtil.isTokenValid(token, user)) {
                Authentication authenticationToken = jwtTokenUtil.getAuthenticationToken(token, authentication, user);

                log.debug("Authenticated user: {}, setting security context", username);
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
        }

        chain.doFilter(request, response);
        
    }
    
}
```

**Web Security Configuration**

Create custom web security configuration without `WebSecurityConfigurerAdapter`

```java
@Slf4j
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfiguration {

    @Autowired
    private UnauthorizedEntryPoint unauthorizedEntryPoint;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, TokenProvider tokenProvider) throws Exception {
        http.httpBasic().and().cors().and().csrf().disable()
            .authorizeHttpRequests()
            .antMatchers("/auth/**").permitAll()
            .anyRequest().authenticated().and()
            .exceptionHandling().authenticationEntryPoint(unauthorizedEntryPoint).and()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.addFilterBefore(new JwtAuthenticationFilter(tokenProvider, userDetailsService()), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(UserService userService, BCryptPasswordEncoder passwordEncoder) throws Exception {
        return authentication -> {
            String username = authentication.getPrincipal().toString();
            String password = authentication.getCredentials().toString();
            User user = (User) userService.loadUserByUsername(username);
            log.info("Credentials password: {}", password);
            log.info("User :: {}", user);

            return new UsernamePasswordAuthenticationToken(username, "", user.getAuthorities());
        };
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**")
                        .allowedMethods("*");
            }
        };
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return new UserService();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().antMatchers("/h2-console/**");
    }
    
}
```

**The Controller**

`AuthController`

```java
@Slf4j
@RestController
@RequestMapping(value = "/auth")
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    @Qualifier("userDetailsService")
    private UserService userService;

    @Autowired
    private TokenProvider jwtTokenUtil;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @PostMapping(value = "/login")
    public ResponseEntity<Object> login(@RequestBody LoginRequest request) {

        User user = (User) userService.loadUserByUsername(request.getUsername());
        log.info("User :: {}", user);

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            return new ResponseEntity<>("Invalid username or password", HttpStatus.UNAUTHORIZED);
        }


        final Authentication authentication = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);
        final String token = jwtTokenUtil.generateToken(authentication);

        return ResponseEntity.ok(new LoginResponse(token));
    }
    
}
```
`UserController`

```java
@RestController
@RequestMapping("/v1/user")
public class UserController {

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping(value="/admin")
    public ResponseEntity<Object> adminPing() {
        return ResponseEntity.ok().body(PingResponse.builder()
                .message("Only admin can view this resource!")
                .build());
    }

    @PreAuthorize("hasRole('USER')")
    @GetMapping(value="/user")
    public ResponseEntity<Object> userPing() {
        return ResponseEntity.ok().body(PingResponse.builder()
                .message("Any user can view this resource!")
                .build());
    }
    
}
```

**Add dummy data on application startup**

```java
@Component
public class ApplicationOnStartup implements ApplicationListener<ApplicationReadyEvent> {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserRoleRepository userRoleRepository;

    @Override
    public void onApplicationEvent(ApplicationReadyEvent event) {
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        User admin = User.builder()
                        .username("admin")
                        .password(passwordEncoder.encode("admin"))
                        .businessTitle("Administrator")
                        .fullName("Maverick J. Robert")
                        .build();
        User user = User.builder()
                        .username("user")
                        .password(passwordEncoder.encode("user"))
                        .businessTitle("Only User")
                        .fullName("User Dummy")
                        .build();
        List<User> users = new ArrayList<>();
        users.add(admin);
        users.add(user);

        userRepository.saveAll(users);

        UserRole adminRoleAdmin = UserRole.builder()
                                .user(admin)
                                .role("ROLE_ADMIN")
                                .build();
        UserRole adminRoleUser = UserRole.builder()
                                .user(admin)
                                .role("ROLE_USER")
                                .build();
        UserRole userRoleUser = UserRole.builder()
                                .user(user)
                                .role("ROLE_USER")
                                .build();
        List<UserRole> userRoles = new ArrayList<>();
        userRoles.add(adminRoleAdmin);
        userRoles.add(adminRoleUser);
        userRoles.add(userRoleUser);

        userRoleRepository.saveAll(userRoles);
    }
    
}
```

## Reference
* [Spring Boot API Security with JWT and Role-Based Authorization](https://medium.com/@akhileshanand/spring-boot-api-security-with-jwt-and-role-based-authorization-fea1fd7c9e32)
* [spring-webmvc-jwt-sample](https://github.com/hantsy/spring-webmvc-jwt-sample)
* [Spring Security without the WebSecurityConfigurerAdapter](https://spring.io/blog/2022/02/21/spring-security-without-the-websecurityconfigureradapter)
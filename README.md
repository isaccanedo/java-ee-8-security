## Java EE 8 Security API

# 1. Visão Geral
A API de segurança Jakarta EE 8 é o novo padrão e uma maneira portátil de lidar com questões de segurança em contêineres Java.

Neste artigo, veremos os três principais recursos da API:

- Mecanismo de autenticação HTTP;
- Loja de Identidade;
- Contexto de Segurança.
Vamos primeiro entender como configurar as implementações fornecidas e, em seguida, como implementar uma personalizada.

# 2. Dependências Maven
Para configurar a API de segurança Jakarta EE 8, precisamos de uma implementação fornecida pelo servidor ou explícita.

### 2.1. Usando a implementação de servidor
Os servidores compatíveis com Jakarta EE 8 já fornecem uma implementação para a API de segurança Jakarta EE 8 e, portanto, precisamos apenas do artefato Maven da API Jakarta EE Web Profile:

```
<dependencies>
    <dependency>
        <groupId>javax</groupId>
        <artifactId>javaee-web-api</artifactId>
        <version>8.0</version>
        <scope>provided</scope>
    </dependency>
</dependencies>
```

### 2.2. Usando uma implementação explícita
Primeiro, especificamos o artefato Maven para a API de segurança Jakarta EE 8:

```
<dependencies>
    <dependency>
        <groupId>javax.security.enterprise</groupId>
        <artifactId>javax.security.enterprise-api</artifactId>
        <version>1.0</version>
    </dependency>
</dependencies>
```

Em seguida, adicionaremos uma implementação, por exemplo, Soteria - a implementação de referência:

```
<dependencies>
    <dependency>
        <groupId>org.glassfish.soteria</groupId>
        <artifactId>javax.security.enterprise</artifactId>
        <version>1.0</version>
    </dependency>
</dependencies>
```

# 3. Mecanismo de autenticação HTTP
Antes de Jakarta EE 8, configuramos mecanismos de autenticação declarativamente por meio do arquivo web.xml.

Nesta versão, a API de segurança Jakarta EE 8 projetou a nova interface HttpAuthenticationMechanism como uma substituição. Portanto, os aplicativos da web agora podem configurar mecanismos de autenticação, fornecendo implementações desta interface.

Felizmente, o contêiner já fornece uma implementação para cada um dos três métodos de autenticação definidos pela especificação Servlet: autenticação HTTP básica, autenticação baseada em formulário e autenticação baseada em formulário personalizado.

Ele também fornece uma anotação para acionar cada implementação:

- @BasicAuthenticationMechanismDefinition;
- @FormAuthenticationMechanismDefinition;
- @CustomFormAuthenrticationMechanismDefinition.

### 3.1. Autenticação HTTP Básica
Conforme mencionado acima, um aplicativo da web pode configurar a autenticação HTTP básica apenas usando a anotação @BasicAuthenticationMechanismDefinition em um bean CDI:

```
@BasicAuthenticationMechanismDefinition(
  realmName = "userRealm")
@ApplicationScoped
public class AppConfig{}
```

Nesse ponto, o contêiner Servlet procura e instancia a implementação fornecida da interface HttpAuthenticationMechanism.

Após o recebimento de uma solicitação não autorizada, o contêiner desafia o cliente a fornecer informações de autenticação adequadas por meio do cabeçalho de resposta WWW-Authenticate.

```
WWW-Authenticate: Basic realm="userRealm"
```

O cliente então envia o nome de usuário e a senha, separados por dois pontos “:” e codificados em Base64, por meio do cabeçalho da solicitação de autorização:

```
//user=baeldung, password=baeldung
Authorization: Basic YmFlbGR1bmc6YmFlbGR1bmc=
```

Observe que a caixa de diálogo apresentada para fornecer credenciais vem do navegador e não do servidor.

### 3.2. Autenticação HTTP baseada em formulário
A anotação @FormAuthenticationMechanismDefinition dispara uma autenticação baseada em formulário conforme definido pela especificação Servlet.

Em seguida, temos a opção de especificar as páginas de login e de erro ou usar as páginas padrão razoáveis /login e /login-error:

```
@FormAuthenticationMechanismDefinition(
  loginToContinue = @LoginToContinue(
    loginPage = "/login.html",
    errorPage = "/login-error.html"))
@ApplicationScoped
public class AppConfig{}
```

Como resultado da invocação de loginPage, o servidor deve enviar o formulário ao cliente:

```
<form action="j_security_check" method="post">
    <input name="j_username" type="text"/>
    <input name="j_password" type="password"/>
    <input type="submit">
</form>
```

O cliente então deve enviar o formulário para um processo de autenticação de apoio predefinido fornecido pelo contêiner.

### 3.3. Autenticação HTTP baseada em formulário personalizado
Um aplicativo da web pode acionar a implementação de autenticação baseada em formulário personalizado usando a anotação @CustomFormAuthenticationMechanismDefinition:

```
@CustomFormAuthenticationMechanismDefinition(
  loginToContinue = @LoginToContinue(loginPage = "/login.xhtml"))
@ApplicationScoped
public class AppConfig {
}
```

Mas, ao contrário da autenticação baseada em formulário padrão, estamos configurando uma página de login personalizada e chamando o método SecurityContext.authenticate() como um processo de autenticação de apoio.

Vamos dar uma olhada no apoio LoginBean também, que contém a lógica de login:

```
@Named
@RequestScoped
public class LoginBean {

    @Inject
    private SecurityContext securityContext;

    @NotNull private String username;

    @NotNull private String password;

    public void login() {
        Credential credential = new UsernamePasswordCredential(
          username, new Password(password));
        AuthenticationStatus status = securityContext
          .authenticate(
            getHttpRequestFromFacesContext(),
            getHttpResponseFromFacesContext(),
            withParams().credential(credential));
        // ...
    }
     
    // ...
}
```

Como resultado da chamada da página login.xhtml personalizada, o cliente submete o formulário recebido ao método login() do LoginBean:

```
//...
<input type="submit" value="Login" jsf:action="#{loginBean.login}"/>
```

### 3.4. Mecanismo de autenticação personalizado
A interface HttpAuthenticationMechanism define três métodos. O mais importante é o validateRequest() que devemos fornecer uma implementação.

O comportamento padrão para os outros dois métodos, secureResponse() e cleanSubject(), é suficiente na maioria dos casos.

Vamos dar uma olhada em um exemplo de implementação:

```
@ApplicationScoped
public class CustomAuthentication 
  implements HttpAuthenticationMechanism {

    @Override
    public AuthenticationStatus validateRequest(
      HttpServletRequest request,
      HttpServletResponse response, 
      HttpMessageContext httpMsgContext) 
      throws AuthenticationException {
 
        String username = request.getParameter("username");
        String password = response.getParameter("password");
        // mocking UserDetail, but in real life, we can obtain it from a database
        UserDetail userDetail = findByUserNameAndPassword(username, password);
        if (userDetail != null) {
            return httpMsgContext.notifyContainerAboutLogin(
              new CustomPrincipal(userDetail),
              new HashSet<>(userDetail.getRoles()));
        }
        return httpMsgContext.responseUnauthorized();
    }
    //...
}
```

Aqui, a implementação fornece a lógica de negócios do processo de validação, mas, na prática, é recomendável delegar ao IdentityStore por meio do IdentityStoreHandler invocando validate.

Também anotamos a implementação com a anotação @ApplicationScoped, pois precisamos torná-la habilitada para CDI.

Após uma verificação válida da credencial e uma eventual recuperação das funções do usuário, a implementação deve notificar o contêiner:

```
HttpMessageContext.notifyContainerAboutLogin(Principal principal, Set groups)
```

### 3.5. Reforçando a segurança do servlet
Um aplicativo da web pode impor restrições de segurança usando a anotação @ServletSecurity em uma implementação de Servlet:

```
@WebServlet("/secured")
@ServletSecurity(
  value = @HttpConstraint(rolesAllowed = {"admin_role"}),
  httpMethodConstraints = {
    @HttpMethodConstraint(
      value = "GET", 
      rolesAllowed = {"user_role"}),
    @HttpMethodConstraint(     
      value = "POST", 
      rolesAllowed = {"admin_role"})
  })
public class SecuredServlet extends HttpServlet {
}
```

Essa anotação possui dois atributos - httpMethodConstraints e value; httpMethodConstraints é usado para especificar uma ou mais restrições, cada uma representando um controle de acesso a um método HTTP por uma lista de funções permitidas.

O contêiner irá então verificar, para cada padrão de url e método HTTP, se o usuário conectado tem a função adequada para acessar o recurso.

# 4. Loja de identidade
Este recurso é abstraído pela interface IdentityStore e é usado para validar credenciais e, eventualmente, recuperar membros do grupo. Em outras palavras, ele pode fornecer recursos de autenticação, autorização ou ambos.

O IdentityStore deve ser usado e recomendado pelo HttpAuthenticationMecanism por meio de uma interface chamada IdentityStoreHandler. Uma implementação padrão do IdentityStoreHandler é fornecida pelo contêiner Servlet.

Um aplicativo pode fornecer sua implementação do IdentityStore ou usar uma das duas implementações integradas fornecidas pelo contêiner para Banco de Dados e LDAP.

### 4.1. Lojas de identidade integradas
O servidor compatível com Jakarta EE deve fornecer implementações para os dois armazenamentos de identidade: banco de dados e LDAP.

A implementação do banco de dados IdentityStore é inicializada passando dados de configuração para a anotação @DataBaseIdentityStoreDefinition:

```
@DatabaseIdentityStoreDefinition(
  dataSourceLookup = "java:comp/env/jdbc/securityDS",
  callerQuery = "select password from users where username = ?",
  groupsQuery = "select GROUPNAME from groups where username = ?",
  priority=30)
@ApplicationScoped
public class AppConfig {
}
```

Como dados de configuração, precisamos de uma fonte de dados JNDI para um banco de dados externo, duas instruções JDBC para verificar o chamador e seus grupos e, finalmente, um parâmetro de prioridade que é usado no caso de múltiplos armazenamentos serem configurados.

IdentityStore com alta prioridade é processado posteriormente pelo IdentityStoreHandler.

Como o banco de dados, a implementação do LDAP IdentityStore é inicializada por meio de @LdapIdentityStoreDefinition, passando os dados de configuração:

```
@LdapIdentityStoreDefinition(
  url = "ldap://localhost:10389",
  callerBaseDn = "ou=caller,dc=baeldung,dc=com",
  groupSearchBase = "ou=group,dc=baeldung,dc=com",
  groupSearchFilter = "(&(member=%s)(objectClass=groupOfNames))")
@ApplicationScoped
public class AppConfig {
}
```

Aqui, precisamos da URL de um servidor LDAP externo, como pesquisar o chamador no diretório LDAP e como recuperar seus grupos.

### 4.2. Implementando um IdentityStore personalizado
A interface IdentityStore define quatro métodos padrão:

```
default CredentialValidationResult validate(
  Credential credential)
default Set<String> getCallerGroups(
  CredentialValidationResult validationResult)
default int priority()
default Set<ValidationType> validationTypes()
```

O método priority() retorna um valor para a ordem de iteração em que esta implementação é processada por IdentityStoreHandler. Um IdentityStore com prioridade mais baixa é tratado primeiro.

Por padrão, um IdentityStore processa a validação de credenciais (ValidationType.VALIDATE) e a recuperação de grupo (ValidationType.PROVIDE_GROUPS). Podemos substituir esse comportamento para que ele possa fornecer apenas um recurso.

Assim, podemos configurar o IdentityStore para ser usado apenas para validação de credenciais:

```
@Override
public Set<ValidationType> validationTypes() {
    return EnumSet.of(ValidationType.VALIDATE);
}
```

Nesse caso, devemos fornecer uma implementação para o método validate():

```
@ApplicationScoped
public class InMemoryIdentityStore implements IdentityStore {
    // init from a file or harcoded
    private Map<String, UserDetails> users = new HashMap<>();

    @Override
    public int priority() {
        return 70;
    }

    @Override
    public Set<ValidationType> validationTypes() {
        return EnumSet.of(ValidationType.VALIDATE);
    }

    public CredentialValidationResult validate( 
      UsernamePasswordCredential credential) {
 
        UserDetails user = users.get(credential.getCaller());
        if (credential.compareTo(user.getLogin(), user.getPassword())) {
            return new CredentialValidationResult(user.getLogin());
        }
        return INVALID_RESULT;
    }
}
```

Ou podemos escolher configurar o IdentityStore para que possa ser usado apenas para recuperação de grupo:

```
@Override
public Set<ValidationType> validationTypes() {
    return EnumSet.of(ValidationType.PROVIDE_GROUPS);
}
```

Devemos então fornecer uma implementação para os métodos getCallerGroups():

```
@ApplicationScoped
public class InMemoryIdentityStore implements IdentityStore {
    // init from a file or harcoded
    private Map<String, UserDetails> users = new HashMap<>();

    @Override
    public int priority() {
        return 90;
    }

    @Override
    public Set<ValidationType> validationTypes() {
        return EnumSet.of(ValidationType.PROVIDE_GROUPS);
    }

    @Override
    public Set<String> getCallerGroups(CredentialValidationResult validationResult) {
        UserDetails user = users.get(
          validationResult.getCallerPrincipal().getName());
        return new HashSet<>(user.getRoles());
    }
}
```

Como IdentityStoreHandler espera que a implementação seja um bean CDI, nós o decoramos com a anotação ApplicationScoped.

# 5. API de contexto de segurança
A API de segurança Jakarta EE 8 fornece um ponto de acesso à segurança programática por meio da interface SecurityContext. É uma alternativa quando o modelo de segurança declarativo imposto pelo contêiner não é suficiente.

Uma implementação padrão da interface SecurityContext deve ser fornecida no tempo de execução como um bean CDI e, portanto, precisamos injetá-lo:

```
@Inject
SecurityContext securityContext;
```

Neste ponto, podemos autenticar o usuário, recuperar um autenticado, verificar sua participação na função e conceder ou negar acesso ao recurso da web por meio dos cinco métodos disponíveis.

### 5.1. Recuperando Dados do Chamador
Nas versões anteriores do Jakarta EE, recuperávamos o Principal ou veríamos a associação da função de maneira diferente em cada contêiner.

Embora usemos os métodos getUserPrincipal() e isUserInRole() do HttpServletRequest em um contêiner de servlet, os métodos getCallerPrincipal() e isCallerInRole() do EJBContext são usados no contêiner EJB.

A nova API de segurança Jakarta EE 8 padronizou isso, fornecendo um método semelhante por meio da interface SecurityContext:

```
Principal getCallerPrincipal();
boolean isCallerInRole(String role);
<T extends Principal> Set<T> getPrincipalsByType(Class<T> type);
```

O método getCallerPrincipal() retorna uma representação específica do contêiner do chamador autenticado, enquanto o método getPrincipalsByType() recupera todos os principais de um determinado tipo.

Pode ser útil no caso de o chamador específico do aplicativo ser diferente do contêiner.

### 5.2 Teste de acesso a recursos da web
Primeiro, precisamos configurar um recurso protegido:

```
@WebServlet("/protectedServlet")
@ServletSecurity(@HttpConstraint(rolesAllowed = "USER_ROLE"))
public class ProtectedServlet extends HttpServlet {
    //...
}
```

E então, para verificar o acesso a este recurso protegido, devemos invocar o método hasAccessToWebResource():

```
securityContext.hasAccessToWebResource("/protectedServlet", "GET");
```

Nesse caso, o método retorna verdadeiro se o usuário estiver na função USER_ROLE.

### 5.3. Autenticar o chamador programaticamente
Um aplicativo pode acionar programaticamente o processo de autenticação invocando authenticate():

```
AuthenticationStatus authenticate(
  HttpServletRequest request, 
  HttpServletResponse response,
  AuthenticationParameters parameters);
```

O contêiner é então notificado e, por sua vez, invoca o mecanismo de autenticação configurado para o aplicativo. O parâmetro AuthenticationParameters fornece uma credencial para HttpAuthenticationMechanism:

```
withParams().credential(credential)
```

Os valores SUCCESS e SEND_FAILURE do AuthenticationStatus projetam uma autenticação bem-sucedida e com falha, enquanto SEND_CONTINUE sinaliza um status em andamento do processo de autenticação.

# 6. Executando os exemplos
Para destacar esses exemplos, usamos a versão de desenvolvimento mais recente do Open Liberty Server que suporta Jakarta EE 8. Isso é baixado e instalado graças ao plug-in liberty-maven, que também pode implementar o aplicativo e iniciar o servidor.

Para executar os exemplos, basta acessar o módulo correspondente e invocar este comando:

```
mvn clean package liberty:run
```

Como resultado, o Maven fará o download do servidor, construirá, implementará e executará o aplicativo.

# 7. Conclusão
Neste artigo, cobrimos a configuração e implementação dos principais recursos do novo Jakarta EE 8 Security API.

Primeiro, começamos mostrando como configurar os mecanismos de autenticação embutidos padrão e como implementar um customizado. Posteriormente, vimos como configurar o Identity Store integrado e como implementar um customizado. E, finalmente, vimos como chamar métodos do SecurityContext.

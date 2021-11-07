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



```


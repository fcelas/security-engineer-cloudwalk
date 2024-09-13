# Security Engineer Challenge - CloudWalk, Inc.

Projeto para o processo seletivo da vaga de Security Engineer da CloudWalk. Desafio proposto foi a criação de um programa em JavaScript que simula o comportamento de um Firewall:
- Allowlist & Blocklist + logs;
- Processamento de tráfego;
- Identificar padrões de tráfego;
- Criar e definir políticas;
- Identificação e gerenciamento de ameaças:
  - Identificar, bloquear e/ou sinalizar tráfego que possa representar uma ameaça potencial.
  - Allowlist.
  - Blocklist onde todo o tráfego proveniente de IPs especificados seja bloqueado por 12 horas.
  - Ações de bloqueio e permissão devem ser rastreáveis e reversíveis.

## Características

- Análise de tráfego HTTP e HTTPS
- Detecção de métodos HTTP suspeitos
- Bloqueio baseado em geolocalização
- Detecção de ataques por padrões de URL
- Blocklist temporária (12 horas)
- Allowlist permanente
- Detecção de possíveis ataques DDoS
- Logging de ações e configurações

## Requisitos

- Node.js (versão 12.0 ou superior)
- npm (normalmente vem com Node.js)

## Estrutura do Projeto

```
src/
│   firewall.js
│   test-dataset.csv
│
├───logs/
│       firewall_log.txt
│       config_log.txt
│
├───listas/
│       blocklist_temp.json
│       allowlist.json
│
└───resultados/
        analise_trafego.json
```

## Instalação

1. Clone o repositório:
   ```
   git clone https://github.com/seu-usuario/firewall-simulado.git
   ```

2. Navegue até o diretório do projeto:
   ```
   cd firewall-simulado
   ```

3. Instale as dependências:
   ```
   npm install
   ```

## Uso

Para executar o firewall simulado:

```
node src/firewall.js
```

Siga as instruções no console para configurar as opções do firewall e analisar o tráfego.

## Funções Principais

### `analisaTrafego(ip, scheme, metodo, pais, path, bytes, porta, host)`
Analisa cada requisição de tráfego e determina se deve ser bloqueada ou permitida.

### `detectarDDoS(ip, porta)`
Detecta possíveis ataques DDoS baseados em múltiplas portas de origem do mesmo IP.

### `adicionarNaBlocklist(ip)` / `adicionarNaAllowList(ip)`
Adiciona um IP à blocklist temporária ou à allowlist permanente.

### `removerDaBlocklist(ip)` / `removerDaAllowlist(ip)`
Remove um IP da blocklist ou allowlist.

### `processarTrafego()`
Lê o arquivo CSV de tráfego e processa cada entrada.

### `logAcao(resultado)` / `logConfig(mensagem)`
Registra ações do firewall e mudanças de configuração.

## Configuração

O firewall permite configurar:
- Bloqueio de requisições HTTP
- Bloqueio de métodos HTTP suspeitos
- Bloqueio baseado em geolocalização suspeita

## Arquivos de Saída

- `logs/firewall_log.txt`: Log de todas as ações do firewall
- `logs/config_log.txt`: Log de mudanças na configuração
- `listas/blocklist_temp.json`: Lista de IPs bloqueados temporariamente
- `listas/allowlist.json`: Lista de IPs permitidos permanentemente
- `resultados/analise_trafego.json`: Resultado da análise de tráfego

# Processo de criação do programa:
## Parâmetros e casos de uso:
- **ClientIP:** Endereço IP de Origem;
  - Bloquear/permitir IPs específicos: Blocklist ou allowlist com base nos endereços IPs conhecidos.
  - Detectar IPs suspeitos: Analisar atividades anômalas como requisições excessivas de um único IP, o que pode ser indicativo de ataques de força bruta ou DDoS.
- **ClientRequestHost:** Host de Destino;
  - Filtragem de Domínios: Bloquear ou permitir requisições para domínios específicos, especialmente se houver hosts maliciosos ou conhecidos por phishing;
- **ClientRequestMethod:** Método HTTP;
  - Detectar tentativas de exploração: Bloquear métodos como:
    - `PUT`
    - `DELETE`
    - `PATCH`
    - `OPTIONS`
- **ClientRequestPath:** URI Requisitada;
  - Inspeção de padrões de URI: Requisições que contêm strings específicas, como ../../ (tentativas de path traversal) ou parâmetros suspeitos, podem indicar ataques de injeção ou exploração de vulnerabilidades.
  - Bloqueio de acessos a URIs específicas: Proteger páginas sensíveis (ex.: /admin, /login, /config).
- **ClientRequestReferer:** Referer da Requisição;
  - Análise de Referência: Verificar se as requisições vêm de sites de referência legítimos. Referers de sites desconhecidos ou maliciosos podem indicar tentativas de redirecionamento ou ataques de phishing.
- **ClientRequestScheme:** Esquema;
  - Bloquear HTTP: Criar opção de política que permita bloquear ou permitir HTTP;
- **ClientRequestUserAgent:** User-Agent;
  - Bloquear User-Agents desconhecidos: Podem ser utilizados por bots;
- **ClientASN:** ASN;
  - Detecção de tráfego de redes conhecidas por atividades maliciosas: Alguns ASN são notórios por serem utilizados por atacantes ou botnets.
- **ClientCountry:** País de Origem;
  - Geofencing: Bloquear tráfego de países ou ASN específicos, dependendo do cenário.
- **ClientRequestBytes:** Volume de Dados;
  - Bloqueio de requisições muito grandes: Detectar e bloquear requisições que excedem um determinado tamanho, já que grandes requisições podem ser indicativas de ataques de negação de serviço (DDoS) ou upload de arquivos maliciosos.
- **EdgeStartTimestamp:** Timestamp;
  - Detecção de tráfego anômalo baseado no tempo: Monitorar a frequência de requisições de um IP em um curto intervalo de tempo, o que pode indicar atividades maliciosas como ataques de força bruta ou DDoS.
- **ClientSrcPort:** Porta de Origem;
  - Análise de portas incomuns: Embora o foco geralmente seja na porta de destino, portas de origem incomuns podem indicar tentativas de disfarçar tráfego malicioso.

## Campos dos logs:
- **Severidade:** diz respeito ao nível de "preocupação" de uma requisição. Ex: requisições em países suspeitos possuem severidade mais alta.
  - 0: info
  - 1: baixa
  - 2: média
  - 3: alta
  - 4: crítica (ataque)







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
- npm 

## Estrutura do Projeto

```
src/
│   js-fw.js
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
   git clone https://github.com/fcelas/security-engineer-cloudwalk
   ```

2. Navegue até o diretório do projeto:
   ```
   cd security-engineer-cloudwalk
   ```

3. Instale as dependências:
   ```
   npm install
   ```

## Uso

Para executar o firewall:

```
node src/js-fw.js
```

Após iniciar o programa, você será apresentado a um menu principal com as seguintes opções:

1. Iniciar análise de tráfego
2. Configurar regras de bloqueio
3. Gerenciar listas (blocklist/allowlist)
4. Ver resultados e listas
5. Sair

Ao iniciar a análise pela primeira vez, alguns IPs serão automaticamente adicionados à blocklist por apresentarem comportamento semelhante a um DDoS.

### Fluxo de Operação

1. **Configurar Regras**: Use a opção 2 do menu principal para configurar as regras de bloqueio antes de iniciar a análise.

2. **Gerenciar Listas**: Use a opção 3 para adicionar ou remover IPs da blocklist e allowlist conforme necessário.

3. **Iniciar Análise**: Selecione a opção 1 para iniciar a análise do tráfego. O programa processará o arquivo CSV de entrada e aplicará as regras configuradas.

4. **Ver Resultados**: Após a análise, o programa retornará automaticamente ao menu principal. Use a opção 4 para visualizar os resultados da análise, as listas de IPs e os logs.

5. **Repetir ou Sair**: Você pode realizar múltiplas análises, ajustar configurações ou gerenciar listas conforme necessário. Use a opção 5 para sair do programa quando terminar.

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
- **ClientRequestHost:** Host de Destino;
- **ClientRequestMethod:** Método HTTP;
- **ClientRequestPath:** URI Requisitada;
- **ClientRequestReferer:** Referer da Requisição;
- **ClientRequestScheme:** Esquema;
- **ClientRequestUserAgent:** User-Agent;
- **ClientASN:** ASN;
- **ClientCountry:** País de Origem;
- **ClientRequestBytes:** Volume de Dados;
- **EdgeStartTimestamp:** Timestamp;
- **ClientSrcPort:** Porta de Origem;

## Tipos de Detecção e Ação

1. **Blocklist Temporária**: 
   - IPs adicionados manualmente ou por detecção de ameaças são bloqueados por 12 horas.
   - Após 12 horas, os IPs são automaticamente removidos da blocklist.

2. **Allowlist Permanente**:
   - IPs adicionados manualmente são sempre permitidos, ignorando outras regras.

3. **Bloqueio de HTTP**:
   - Opção para bloquear todas as requisições HTTP, permitindo apenas HTTPS.

4. **Detecção de Métodos HTTP Suspeitos**:
   - Bloqueia métodos como PUT, DELETE, PATCH, OPTIONS quando ativado.

5. **Bloqueio por Geolocalização**:
   - Opção para bloquear tráfego de países considerados de risco (ex: 'cn' para China).

6. **Detecção de Padrões de Ataque**:
   - Usa expressões regulares para identificar padrões de ataques conhecidos nas URLs.
   - Inclui detecção de XSS, injeção de SQL, tentativas de path traversal, entre outros.

7. **Limite de Tamanho de Requisição**:
   - Bloqueia requisições com mais de 4000 bytes para prevenir ataques de sobrecarga.

8. **Detecção de DDoS**:
   - Monitora o número de portas diferentes usadas por um único IP em um curto período.
   - Bloqueia o IP se exceder um limite predefinido de portas únicas.

9. **Logging de Ações**:
   - Todas as ações do firewall são registradas para auditoria e análise posterior.

10. **Configuração Dinâmica**:
    - Permite ativar/desativar diferentes mecanismos de proteção através de um menu interativo.

## Campos dos logs:
- **Severidade:** diz respeito ao nível de "preocupação" de uma requisição. Ex: requisições em países suspeitos possuem severidade mais alta.
  - 0: info
  - 1: baixa
  - 2: média
  - 3: alta
  - 4: crítica (ataque)







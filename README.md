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
- **Action:** 
  - Permit: tráfego liberado;
  - Drop: tráfego dropado;
  - Allow: tráfego permitido;
  - Block: tráfego bloqueado;
- **Severidade:** diz respeito ao nível de "preocupação" de uma requisição. Ex: requisições em países suspeitos possuem severidade mais alta.
  - 0: info
  - 1: baixa
  - 2: média
  - 3: alta
  - 4: crítica (ataque)

## Regras e Políticas do FW:
**1. Verifica se IP de Origem está em Blocklist ou Allowlist;**
**2. Verifica se esquema HTTP deve ser bloqueado;**
**3. Bloqueia métodos suspeitos;**




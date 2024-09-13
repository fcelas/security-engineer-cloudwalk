const fs = require('fs');
const csv = require('csv-parser');
const readline = require('readline');
const path = require('path');

const LOG_DIR = path.join(__dirname, 'logs');
const LIST_DIR = path.join(__dirname, 'listas');
const RESULT_DIR = path.join(__dirname, 'resultados');

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

let blocklist = new Map();
let allowlist = new Map();

let bloquearHTTP = false;
let bloquearMetodos = false;
let bloquearGeoSuspeito = false;
let resultados = [];

const metodosSuspeitos = ['PUT', 'DELETE', 'PATCH', 'OPTIONS']
const paisesSuspeitos = ['cn']

const regexMap = [
    { regex: /\/";!--"<XSS>=&\{\(\)\}/, descricao: 'ataque XSS' },
    { regex: /\/%00%01%02%03%04%05%06%07/, descricao: 'URL Encoding' },
    { regex: /(?:\/\.\.){10}\/etc\/shadow/, descricao: 'Path Traversal - /etc/shadow' },
    { regex: /(?:\/\.\.){4}\/windows\/system32\/cmd\.exe/, descricao: 'Path Traversal - /windows/system32/cmd.exe' },
    { regex: /(?:\/\.\.){3}\/etc\/passwd/, descricao: 'Path Traversal - /etc/passwd' },
    { regex: /(?:\/\.\.){3}\/windows\/win\.ini/, descricao: 'Path Traversal - /windows/win.ini' },
    { regex: /(?:\/\.\.){2}\/boot\.ini/, descricao: 'Path Traversal - /boot.ini' },
    { regex: /\/\.git\/config/, descricao: 'Exposure of .git/config' },
    { regex: /<iframe src=['"]javascript:alert\(1\)['"]><\/iframe>/, descricao: 'ataque XSS via iframe' },
    { regex: /<img src=['"]x['"] onerror=['"]alert\(1\)['"]>/, descricao: 'ataque XSS via img' },
    { regex: /<marquee><img src=['"]1['"] onerror=['"]alert\(1\)['"]><\/marquee>/, descricao: 'ataque XSS via marquee' },
    { regex: /<meta http-equiv=['"]refresh['"] content=['"]0;url=javascript:alert\(1\)['"]>/, descricao: 'ataque XSS via meta refresh' },
    { regex: /<script>alert\(['"]XSS['"]\)<\/script>/, descricao: 'ataque XSS via script' }
];

const portasPorIP = new Map();
const limiteDePorts = 10;
const intervaloDeTempoMS = 60000;

function detectarDDoS(ip, porta) {
    const agora = Date.now();
    if (!portasPorIP.has(ip)) {
        portasPorIP.set(ip, { portas: new Set([porta]), ultimoCheck: agora });
        return false;
    }

    const dados = portasPorIP.get(ip);
    if (agora - dados.ultimoCheck > intervaloDeTempoMS) {
        dados.portas.clear();
        dados.ultimoCheck = agora;
    }

    dados.portas.add(porta);
    return dados.portas.size > limiteDePorts;
}

function logConfig(mensagem) {
    const logEntry = `${new Date().toISOString()} - ${mensagem}\n`;
    fs.appendFileSync(path.join(LOG_DIR, 'config_log.txt'), logEntry);
}

function adicionarNaBlocklist(ip) {
    const agora = Date.now();
    blocklist.set(ip, agora);
    salvarBlocklist();
    console.log(`IP ${ip} adicionado à blocklist temporária.`);
    logConfig(`IP ${ip} adicionado à blocklist temporária.`);
}

function removerDaBlocklist(ip) {
    if (blocklist.has(ip)) {
        blocklist.delete(ip);
        salvarBlocklist();
        console.log(`IP ${ip} removido da blocklist.`);
        logConfig(`IP ${ip} removido da blocklist.`);
    } else {
        console.log(`IP ${ip} não encontrado na blocklist.`);
    }
}

function estaNaBlocklist(ip) {
    if (blocklist.has(ip)) {
        const tempoAdicionado = blocklist.get(ip);
        const agora = Date.now();
        const diferencaTempo = agora - tempoAdicionado;
        const dozeHorasEmMs = 12 * 60 * 60 * 1000;

        if (diferencaTempo < dozeHorasEmMs) {
            return true;
        } else {
            blocklist.delete(ip);
            salvarBlocklist();
            console.log(`IP ${ip} removido da blocklist temporária após 12 horas.`);
            logConfig(`IP ${ip} removido da blocklist temporária após 12 horas.`);
            return false;
        }
    }
    return false;
}

function limparBlocklistExpirada() {
    const agora = Date.now();
    const dozeHorasEmMs = 12 * 60 * 60 * 1000;

    for (let [ip, tempo] of blocklist) {
        if (agora - tempo >= dozeHorasEmMs) {
            blocklist.delete(ip);
            console.log(`IP ${ip} removido da blocklist temporária durante limpeza.`);
            logConfig(`IP ${ip} removido da blocklist temporária durante limpeza.`);
        }
    }
    salvarBlocklist();
}

function salvarBlocklist() {
    const dados = JSON.stringify(Array.from(blocklist.entries()));
    fs.writeFileSync(path.join(LIST_DIR, 'blocklist_temp.json'), dados);
}

function carregarBlocklist() {
    try {
        const dados = fs.readFileSync(path.join(LIST_DIR, 'blocklist_temp.json'), 'utf-8');
        blocklist = new Map(JSON.parse(dados));
        console.log('Blocklist temporária carregada do arquivo.');
        logConfig('Blocklist temporária carregada do arquivo.');
    } catch (error) {
        console.log('Arquivo de blocklist não encontrado. Criando uma nova blocklist.');
        logConfig('Arquivo de blocklist não encontrado. Criando uma nova blocklist.');
    }
}

function adicionarNaAllowList(ip) {
    allowlist.set(ip, true);
    salvarAllowlist();
    console.log(`IP ${ip} adicionado à allowlist.`);
    logConfig(`IP ${ip} adicionado à allowlist.`);
}

function removerDaAllowlist(ip) {
    if (allowlist.has(ip)) {
        allowlist.delete(ip);
        salvarAllowlist();
        console.log(`IP ${ip} removido da allowlist.`);
        logConfig(`IP ${ip} removido da allowlist.`);
    } else {
        console.log(`IP ${ip} não encontrado na allowlist.`);
    }
}

function salvarAllowlist() {
    const dados = JSON.stringify(Array.from(allowlist.entries()));
    fs.writeFileSync(path.join(LIST_DIR, 'allowlist.json'), dados);
}

function carregarAllowlist() {
    try {
        const dados = fs.readFileSync(path.join(LIST_DIR, 'allowlist.json'), 'utf-8');
        allowlist = new Map(JSON.parse(dados));
        console.log('Allowlist carregada do arquivo.');
        logConfig('Allowlist carregada do arquivo.');
    } catch (error) {
        console.log('Arquivo de allowlist não encontrado. Criando uma nova allowlist.');
        logConfig('Arquivo de allowlist não encontrado. Criando uma nova allowlist.');
    }
}

function analisaTrafego(ip, scheme, metodo, pais, path, bytes, porta, host) {
    let resultado = { status: '', ip: ip, scheme: scheme, metodo: metodo, pais: pais, severidade: '0', path: path, destino: host };

    if (estaNaBlocklist(ip)) {
        resultado.status = 'Tráfego bloqueado: blocklist temporária';
        resultado.severidade = '0';
    } else if (allowlist.has(ip)) {
        resultado.status = 'Tráfego permitido: allowlist';
    } else if (detectarDDoS(ip, porta)) {
        resultado.status = 'Tráfego bloqueado: Possível ataque DDoS detectado';
        resultado.severidade = '4';
        adicionarNaBlocklist(ip);
        logConfig(`Possível ataque DDoS detectado do IP ${ip}. IP adicionado à blocklist.`);
    } else {
        if (!bloquearHTTP && scheme === 'http') {
            resultado.status = 'Tráfego HTTP permitido';
            resultado.severidade = '3'
        } else if (bloquearHTTP && scheme === 'http') {
            resultado.status = 'Tráfego bloqueado: HTTP não permitido';
            resultado.severidade = '3'
        } else {
            resultado.status = 'Tráfego desconhecido permitido';
        }

        if (!bloquearGeoSuspeito && paisesSuspeitos.includes(pais)) {
            resultado.severidade = '3'
            resultado.status = 'Tráfego permitido: origem do tráfego geolocalizada em país de risco.'
        } else if (bloquearGeoSuspeito && paisesSuspeitos.includes(pais)) {
            resultado.severidade = '3'
            resultado.status = 'Tráfego bloqueado: origem do tráfego geolocalizada em país de risco.'
        } 

        if (!bloquearMetodos && metodosSuspeitos.includes(metodo)) {
            resultado.status = `Tráfego permitido: Método HTTP ${metodo} não permitido`;
        } else if (bloquearMetodos && metodosSuspeitos.includes(metodo)) {
            resultado.status = `Tráfego bloqueado: Método HTTP ${metodo} não permitido`;
        }

        const ataqueDetectado = regexMap.find(({ regex }) => regex.test(path));
        if (ataqueDetectado) {
            resultado.status = `Tráfego bloqueado: ${ataqueDetectado.descricao}`;
            resultado.severidade = '4';
        }

        if (bytes > 4000) {
            resultado.severidade = '4'
            resultado.status = `Tráfego bloqueado: requisição de ${bytes}B excede limite máximo de tamanho`
        }
    }

    resultados.push(resultado);
    logAcao(resultado);
}


function logAcao(resultado) {
    const logEntry = `${new Date().toISOString()} - IP: ${resultado.ip}, Status: ${resultado.status}, Severidade: ${resultado.severidade}\n`;
    fs.appendFileSync(path.join(LOG_DIR, 'firewall_log.txt'), logEntry);
}

function perguntas() {
    rl.question('Deseja bloquear requisições HTTP? (s/n): ', (answerHTTP) => {
        if (answerHTTP.toLowerCase() === 's') {
            bloquearHTTP = true;
            logConfig('Bloqueio de requisições HTTP ativado.');
        } else {
            logConfig('Bloqueio de requisições HTTP desativado.');
        }

        rl.question('Bloquear métodos suspeitos? (s/n): ', (answerMetodos) => {
            if (answerMetodos.toLowerCase() === 's') {
                bloquearMetodos = true;
                logConfig('Bloqueio de métodos suspeitos ativado.');
            } else {
                logConfig('Bloqueio de métodos suspeitos desativado.');
            }

            rl.question('Bloquear Geolocalização suspeita? (s/n): ', (answerGeo) => {
                if (answerGeo.toLowerCase() === 's') {
                    bloquearGeoSuspeito = true;
                    logConfig('Bloqueio de geolocalização suspeita ativado.');
                } else {
                    logConfig('Bloqueio de geolocalização suspeita desativado.');
                }
            
                processarTrafego();
            });
        });
    });
}

function processarTrafego() {
    fs.createReadStream(path.join(__dirname, 'test-dataset.csv'))
        .pipe(csv())
        .on('data', (row) => {
            const ipOrigem = row.ClientIP;
            const scheme = row.ClientRequestScheme.toLowerCase();
            const metodo = row.ClientRequestMethod.toUpperCase();
            const pais = row.ClientCountry.toLowerCase();
            const path = row.ClientRequestPath;
            const bytes = row.ClientRequestBytes;
            const porta = row.ClientSrcPort;
            const host = row.ClientRequestHost;
            analisaTrafego(ipOrigem, scheme, metodo, pais, path, bytes, porta, host);
        })
        .on('end', () => {
            fs.writeFileSync(path.join(RESULT_DIR, 'analise_trafego.json'), JSON.stringify(resultados, null, 2));
            console.log('Análise de tráfego concluída. Resultados salvos no arquivo analise_trafego.json.');
            logConfig('Análise de tráfego concluída. Resultados salvos no arquivo analise_trafego.json.');
            
            exibirMenuPrincipal();
        });
}


let intervaloLimpeza;

function iniciarLimpezaPeriodica() {
    intervaloLimpeza = setInterval(limparBlocklistExpirada, 60 * 60 * 1000);
    logConfig('Limpeza periódica da blocklist iniciada.');
}

function pararLimpezaPeriodica() {
    if (intervaloLimpeza) {
        clearInterval(intervaloLimpeza);
        logConfig('Limpeza periódica da blocklist interrompida.');
    }
}

function perguntarAdicionarIP() {
    rl.question('Deseja adicionar algum IP à blocklist? (s/n): ', (resposta) => {
        if (resposta.toLowerCase() === 's') {
            rl.question('Digite o IP que deseja adicionar à blocklist: ', (ip) => {
                adicionarNaBlocklist(ip);
                perguntarAdicionarIP(); 
            });
        } else {
            perguntarRemoverIPBlock();
        }
    });
}

function perguntarRemoverIPBlock() {
    rl.question('Deseja remover algum IP da blocklist? (s/n): ', (resposta) => {
        if (resposta.toLowerCase() === 's') {
            rl.question('Digite o IP que deseja remover da blocklist: ', (ip) => {
                removerDaBlocklist(ip);
                perguntarRemoverIPBlock();
            });
        } else {
            perguntarAdicionarIPAllow();
        }
    });
}

function perguntarAdicionarIPAllow() {
    rl.question('Deseja adicionar algum IP à Allowlist? (s/n): ', (resposta) => {
        if (resposta.toLowerCase() === 's') {
            rl.question('Digite o IP que deseja adicionar à allowlist: ', (ip) => {
                adicionarNaAllowList(ip);
                perguntarAdicionarIPAllow(); 
            });
        } else {
            perguntarRemoverIPAllow();
        }
    });
}

function perguntarRemoverIPAllow() {
    rl.question('Deseja remover algum IP da Allowlist? (s/n): ', (resposta) => {
        if (resposta.toLowerCase() === 's') {
            rl.question('Digite o IP que deseja remover da allowlist: ', (ip) => {
                removerDaAllowlist(ip);
                perguntarRemoverIPAllow();
            });
        } else {
            console.log('Análise finalizada. Encerrando o programa.');
            logConfig('Análise finalizada. Programa encerrado.');
            pararLimpezaPeriodica();
            rl.close();
            process.exit(0);
        }
    });
}

//Menu foi feito com auxílio do ChatGPT

function exibirMenuPrincipal() {
    console.log('\n--- Menu Principal ---');
    console.log('1. Iniciar análise de tráfego');
    console.log('2. Configurar regras de bloqueio');
    console.log('3. Gerenciar listas (blocklist/allowlist)');
    console.log('4. Ver resultados e listas');
    console.log('5. Sair');
    rl.question('Escolha uma opção: ', (opcao) => {
        switch (opcao) {
            case '1':
                processarTrafego();
                break;
            case '2':
                menuConfigurarRegras();
                break;
            case '3':
                menuGerenciarListas();
                break;
            case '4':
                menuVerResultados();
                break;
            case '5':
                console.log('Encerrando o programa...');
                rl.close();
                process.exit(0);
            default:
                console.log('Opção inválida.');
                exibirMenuPrincipal();
        }
    });
}


function menuConfigurarRegras() {
    console.log('\n--- Configurar Regras de Bloqueio ---');
    console.log(`1. Bloquear requisições HTTP (atual: ${bloquearHTTP ? 'Sim' : 'Não'})`);
    console.log(`2. Bloquear métodos suspeitos (atual: ${bloquearMetodos ? 'Sim' : 'Não'})`);
    console.log(`3. Bloquear geolocalização suspeita (atual: ${bloquearGeoSuspeito ? 'Sim' : 'Não'})`);
    console.log('4. Voltar ao menu principal');
    rl.question('Escolha uma opção: ', (opcao) => {
        switch (opcao) {
            case '1':
                bloquearHTTP = !bloquearHTTP;
                logConfig(`Bloqueio de requisições HTTP ${bloquearHTTP ? 'ativado' : 'desativado'}.`);
                menuConfigurarRegras();
                break;
            case '2':
                bloquearMetodos = !bloquearMetodos;
                logConfig(`Bloqueio de métodos suspeitos ${bloquearMetodos ? 'ativado' : 'desativado'}.`);
                menuConfigurarRegras();
                break;
            case '3':
                bloquearGeoSuspeito = !bloquearGeoSuspeito;
                logConfig(`Bloqueio de geolocalização suspeita ${bloquearGeoSuspeito ? 'ativado' : 'desativado'}.`);
                menuConfigurarRegras();
                break;
            case '4':
                exibirMenuPrincipal();
                break;
            default:
                console.log('Opção inválida.');
                menuConfigurarRegras();
        }
    });
}

function menuGerenciarListas() {
    console.log('\n--- Gerenciar Listas ---');
    console.log('1. Adicionar IP à blocklist');
    console.log('2. Remover IP da blocklist');
    console.log('3. Adicionar IP à allowlist');
    console.log('4. Remover IP da allowlist');
    console.log('5. Voltar ao menu principal');
    rl.question('Escolha uma opção: ', (opcao) => {
        switch (opcao) {
            case '1':
                rl.question('Digite o IP para adicionar à blocklist: ', (ip) => {
                    adicionarNaBlocklist(ip);
                    menuGerenciarListas();
                });
                break;
            case '2':
                rl.question('Digite o IP para remover da blocklist: ', (ip) => {
                    removerDaBlocklist(ip);
                    menuGerenciarListas();
                });
                break;
            case '3':
                rl.question('Digite o IP para adicionar à allowlist: ', (ip) => {
                    adicionarNaAllowList(ip);
                    menuGerenciarListas();
                });
                break;
            case '4':
                rl.question('Digite o IP para remover da allowlist: ', (ip) => {
                    removerDaAllowlist(ip);
                    menuGerenciarListas();
                });
                break;
            case '5':
                exibirMenuPrincipal();
                break;
            default:
                console.log('Opção inválida.');
                menuGerenciarListas();
        }
    });
}

function menuVerResultados() {
    console.log('\n--- Ver Resultados e Listas ---');
    console.log('1. Ver resultados da última análise');
    console.log('2. Ver blocklist');
    console.log('3. Ver allowlist');
    console.log('4. Ver logs de configuração');
    console.log('5. Ver logs de firewall');
    console.log('6. Voltar ao menu principal');
    rl.question('Escolha uma opção: ', (opcao) => {
        switch (opcao) {
            case '1':
                console.log(JSON.stringify(resultados, null, 2));
                menuVerResultados();
                break;
            case '2':
                console.log(JSON.stringify(Array.from(blocklist.entries()), null, 2));
                menuVerResultados();
                break;
            case '3':
                console.log(JSON.stringify(Array.from(allowlist.entries()), null, 2));
                menuVerResultados();
                break;
            case '4':
                fs.readFile(path.join(LOG_DIR, 'config_log.txt'), 'utf8', (err, data) => {
                    if (err) {
                        console.log('Erro ao ler o arquivo de log de configuração:', err);
                    } else {
                        console.log(data);
                    }
                    menuVerResultados();
                });
                break;
            case '5':
                fs.readFile(path.join(LOG_DIR, 'firewall_log.txt'), 'utf8', (err, data) => {
                    if (err) {
                        console.log('Erro ao ler o arquivo de log do firewall:', err);
                    } else {
                        console.log(data);
                    }
                    menuVerResultados();
                });
                break;
            case '6':
                exibirMenuPrincipal();
                break;
            default:
                console.log('Opção inválida.');
                menuVerResultados();
        }
    });
}

function iniciarPrograma() {
    console.log('Iniciando o firewall...');
    carregarAllowlist();
    carregarBlocklist();
    iniciarLimpezaPeriodica()
    limparBlocklistExpirada();
    exibirMenuPrincipal();
}

iniciarPrograma();

/*
logConfig('Iniciando o firewall...');
carregarAllowlist();
carregarBlocklist();
iniciarLimpezaPeriodica();
perguntas();
*/
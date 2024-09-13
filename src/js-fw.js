const fs = require('fs');
const csv = require('csv-parser');
const readline = require('readline');

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

let blocklist = new Map();
let allowlist = new Map();
//const allowlist = fs.readFileSync('allowlist.txt', 'utf-8').split('\n').map(ip => ip.trim());

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

function adicionarNaBlocklist(ip) {
    const agora = Date.now();
    blocklist.set(ip, agora);
    salvarBlocklist();
    console.log(`IP ${ip} adicionado à blocklist temporária.`);
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
        }
    }
    salvarBlocklist();
}

function salvarBlocklist() {
    const dados = JSON.stringify(Array.from(blocklist.entries()));
    fs.writeFileSync('blocklist_temp.json', dados);
}

function carregarBlocklist() {
    try {
        const dados = fs.readFileSync('blocklist_temp.json', 'utf-8');
        blocklist = new Map(JSON.parse(dados));
        console.log('Blocklist temporária carregada do arquivo.');
    } catch (error) {
        console.log('Arquivo de blocklist não encontrado. Criando uma nova blocklist.');
    }
}

function adicionarNaAllowList(ip) {
    const agora = Date.now();
    allowlist.set(ip, agora);
    salvarAllowlist();
    console.log(`IP ${ip} adicionado à allowlist.`);
}

function salvarAllowlist() {
    const dados = JSON.stringify(Array.from(allowlist.entries()));
    fs.writeFileSync('allowlist.json', dados);
}

function carregarAllowlist() {
    try {
        const dados = fs.readFileSync('allowlist.json', 'utf-8');
        blocklist = new Map(JSON.parse(dados));
        console.log('Allowlist carregada do arquivo.');
    } catch (error) {
        console.log('Arquivo de allowlist não encontrado. Criando uma nova allowlist.');
    }
}

function analisaTrafego(ip, scheme, metodo, pais, path, bytes) {
    let resultado = { status: '', ip: ip, scheme: scheme, metodo: metodo, pais: pais, severidade: '0', path: path };

    if (estaNaBlocklist(ip)) {
        resultado.status = 'Tráfego bloqueado: blocklist temporária';
        resultado.severidade = '4';
    } else if (allowlist.has(ip)) {
        resultado.status = 'Tráfego permitido: allowlist';
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
            resultado.status = `Tráfego bloqueado:  requisição de ${bytes}B excede limite máximo de tamanho`
        }
    }

    resultados.push(resultado);
    logAcao(resultado);
}

function logAcao(resultado) {
    const logEntry = `${new Date().toISOString()} - IP: ${resultado.ip}, Status: ${resultado.status}, Severidade: ${resultado.severidade}\n`;
    fs.appendFileSync('firewall_log.txt', logEntry);
}

function perguntas() {
    rl.question('Deseja bloquear requisições HTTP? (s/n): ', (answerHTTP) => {
        if (answerHTTP.toLowerCase() === 's') {
            bloquearHTTP = true;
        } 

        rl.question('Bloquear métodos suspeitos? (s/n): ', (answerMetodos) => {
            if (answerMetodos.toLowerCase() === 's') {
                bloquearMetodos = true;
            }

            rl.question('Bloquear Geolocalização suspeita? (s/n): ', (answerGeo) => {
                if (answerGeo.toLowerCase() === 's') {
                    bloquearGeoSuspeito = true;
                }
            
                processarTrafego();
            });
        });
    });
}

function processarTrafego() {
    fs.createReadStream('test-dataset.csv')
        .pipe(csv())
        .on('data', (row) => {
            const ipOrigem = row.ClientIP;
            const scheme = row.ClientRequestScheme.toLowerCase();
            const metodo = row.ClientRequestMethod.toUpperCase();
            const pais = row.ClientCountry.toLowerCase();
            const path = row.ClientRequestPath;
            const bytes = row.ClientRequestBytes;
            analisaTrafego(ipOrigem, scheme, metodo, pais, path, bytes);
        })
        .on('end', () => {
            fs.writeFileSync('analise_trafego.json', JSON.stringify(resultados, null, 2));
            console.log('Análise de tráfego concluída. Resultados salvos no arquivo analise_trafego.json.');
            perguntarAdicionarIP();
            perguntarAdicionarIPAllow()
        });
}

let intervaloLimpeza;

function iniciarLimpezaPeriodica() {
    intervaloLimpeza = setInterval(limparBlocklistExpirada, 60 * 60 * 1000);
}

function pararLimpezaPeriodica() {
    if (intervaloLimpeza) {
        clearInterval(intervaloLimpeza);
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
            pararLimpezaPeriodica();
            rl.close();
 
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
            console.log('Análise finalizada. Encerrando o programa.');
            rl.close();
            process.exit(0); 
        }
    });
}

carregarAllowlist()
carregarBlocklist();
iniciarLimpezaPeriodica(); 
perguntas();
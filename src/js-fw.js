const fs = require('fs');
const csv = require('csv-parser');
const readline = require('readline');

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

const blocklist = fs.readFileSync('blocklist.txt', 'utf-8').split('\n').map(ip => ip.trim());
const allowlist = fs.readFileSync('allowlist.txt', 'utf-8').split('\n').map(ip => ip.trim());

let bloquearHTTP = false;
let bloquearMetodos = false;
let bloquearGeoSuspeito = false;
let resultados = [];

//listas de métodos e países de origem suspeitos
const metodosSuspeitos = ['PUT', 'DELETE', 'PATCH', 'OPTIONS']
const paisesSuspeitos = ['cn']

//regex de ataques
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

//função que analisa tráfego
function analisaTrafego(ip, scheme, metodo, pais, path) {
    let resultado = { status: '', ip: ip, scheme: scheme, metodo: metodo, pais: pais, severidade: '0', path: path };

    if (blocklist.includes(ip)) {
        resultado.status = 'Tráfego bloqueado: blocklist';
    } else if (allowlist.includes(ip)) {
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
    }

    resultados.push(resultado);
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
        
    

    fs.createReadStream('test-dataset.csv')
        .pipe(csv())
        .on('data', (row) => {
            const ipOrigem = row.ClientIP;
            const scheme = row.ClientRequestScheme.toLowerCase();
            const metodo = row.ClientRequestMethod.toUpperCase();
            const pais = row.ClientCountry.toLowerCase();
            const path = row.ClientRequestPath;
            analisaTrafego(ipOrigem, scheme, metodo, pais, path);
        })
        .on('end', () => {
            fs.writeFileSync('analise_trafego.json', JSON.stringify(resultados, null, 2));

            console.log('Análise de tráfego concluída. Resultados salvos no arquivo analise_trafego.json.');
            rl.close();
        });
    })
    })
});

}

perguntas();




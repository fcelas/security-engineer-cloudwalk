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

const metodosSuspeitos = ['PUT', 'DELETE', 'PATCH', 'OPTIONS']
const paisesSuspeitos = ['cn', 'us']


function analisaTrafego(ip, scheme, metodo, pais) {
    let resultado = { ip: ip, scheme: scheme, metodo: metodo, pais: pais, severidade: '0', status: '' };

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
            analisaTrafego(ipOrigem, scheme, metodo, pais);
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




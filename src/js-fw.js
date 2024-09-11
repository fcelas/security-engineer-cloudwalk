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
let bloquearMetodo = true;
let bloquearPaisSuspeito = true;
let resultados = [];

const metodos = ['PUT', 'DELETE', 'PATCH', 'OPTIONS']
const paises = ['cn']

function verificarIP(ip, scheme, metodo) {
    let resultado = { ip: ip, scheme: scheme, metodo: metodo, pais: pais, status: '' };

    if (blocklist.includes(ip)) {
        resultado.status = 'Tráfego bloqueado: blocklist';
    } else if (allowlist.includes(ip)) {
        resultado.status = 'Tráfego permitido: allowlist';
    } else {
        resultado.status = 'Tráfego desconhecido permitido';

        if (bloquearHTTP && scheme === 'http') {
            resultado.status = 'Tráfego bloqueado: HTTP não permitido';
        } else if (bloquearMetodo && metodo in metodos) {
            resultado.status = 'Tráfego bloqueado: método não permitido'
        } else if (flagPaisSuspeito && paisSuspeito in paises) {
            resultado.status = 'Tráfego bloqueado: método não permitido'
        }
    }

    resultados.push(resultado);
}

rl.question('Deseja bloquear requisições HTTP? (sim/não): ', (answer) => {
    if (answer.toLowerCase() === 'sim') {
        bloquearHTTP = true;
    }

    fs.createReadStream('test-dataset.csv')
        .pipe(csv())
        .on('data', (row) => {
            const ipOrigem = row.ClientIP;
            const scheme = row.ClientRequestScheme.toLowerCase();
            const metodo = row.ClientRequestMethod;
            verificarIP(ipOrigem, scheme, metodo);
        })
        .on('end', () => {
            fs.writeFileSync('analise_trafego.json', JSON.stringify(resultados, null, 2));

            console.log('Análise de tráfego concluída. Resultados salvos no arquivo analise_trafego.json.');
            rl.close();
        });
});

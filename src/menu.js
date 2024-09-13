const readline = require('readline');
const { exec } = require('child_process');

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

const data = require('./blocklist_temp.json');

function mainMenu() {
    console.log("\nBem-vindo ao Firewall CloudWalk, Inc.\n\nSelecione uma opção:");
    console.log("1. Menu");
    console.log("2. Sair");
    rl.question("Digite sua escolha: ", (answer) => {
        if (answer === '1' || answer.toLowerCase() === 'menu') {
            menuComandos();
        } else if (answer === '2' || answer.toLowerCase() === 'sair') {
            rl.close();
        } else {
            console.log("Opção inválida.");
            mainMenu(); 
        }
    });
}

function menuComandos() {
    console.log("\nMenu principal:\n");
    console.log("Selecione uma opcao:")
    console.log("1. Realizar Análise de Tráfego");
    console.log("2. Configurações");
    console.log("3. Voltar ao menu principal");
    rl.question("Digite sua escolha: ", (answer) => {
        if (answer === '1') {
            console.log("Você escolheu o Realizar Análise de Tráfego");
            menuAnalise(); 
        } else if (answer === '2') {
            console.log("Você escolheu o Configurações");
            menuConfig();
        } else if (answer === '3') {
            mainMenu();
        } else {
            console.log("Opção inválida.");
            menuComandos();
        }
    });
}

function menuAnalise() {
    console.log("\nAnálise de Tráfego\n")
    console.log("Selecione dados para análise:")
    console.log("1. Default (test-dataset.csv)")
    console.log("2. Outro")
    console.log("3. Voltar")
    rl.question("Digite sua escolha: ", (answer) => {
        if (answer === '1') {
            console.log("Você selecionou dados default")
            scriptFW();
        } else if (answer === '3') {
            mainMenu();
        } else {
            console.log("Opção inválida.");
            menuComandos();
        }
    })
}

function scriptFW() {
    exec('node ./js-fw.js', (error, stdout, stderr) => {
        if (error) {
            console.error(`Erro ao executar o script: ${error.message}`);
            return;
        }
        if (stderr) {
            console.error(`Erro no script: ${stderr}`);
            return;
        }
        console.log(`Saída do script: ${stdout}`);
    });
}

function menuConfig() {
    console.log("\n Configuracoes\n")
    console.log("Selecione uma opcao:")
    console.log("1. Blocklist")
    console.log("2. Allowlist")
    console.log("3. Regras e Politicas")
    console.log("4. Voltar")
    rl.question("Digite sua escolha: ", (answer) => {
        if (answer === '1') {
            console.log("Você selecionou Blocklist")
            menuBlocklist();
        } else if (answer === '2') {
            console.log("Você selecionou Allowlist")
            menuAllowlist();
        } else if (answer === '3') {
            console.log("Você selecionou Regras e Politicas")
            menuRegras();
        } else if (answer === '4') {
            menuAnalise();
        }else {
            console.log("Opção inválida.");
            menuComandos();
        }
    })
}

function menuBlocklist() {
    console.log("\n Blocklist\n")
    console.log("Selecione uma opcao:")
    console.log("1. Visualizar Blocklist")
    console.log("2. Adicionar IP em Blocklist")
    console.log("3. Retirar IP de Blocklist")
    console.log("4. Voltar")
    rl.question("Digite sua escolha: ", (answer) => {
        if (answer === '1') {
            console.log("Abrindo Blocklist...   ")
            mostraBlocklist();
        } else if (answer === '2') {
            console.log("Você selecionou Allowlist")
            menuAllowlist();
        } else if (answer === '3') {
            console.log("Você selecionou Regras e Politicas")
            menuRegras();
        } else if (answer === '4') {
            menuAnalise();
        }else {
            console.log("Opção inválida.");
            menuComandos();
        }
    })
}

function mostraBlocklist() {
    console.log(JSON.stringify(data, null, 2)); 
    menuComandos(); 
}

mainMenu();
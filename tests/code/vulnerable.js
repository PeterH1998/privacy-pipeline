// vulnerable_command_injection.js
const { exec } = require("child_process");

function runCommand(userInput) {
    exec(userInput, (error, stdout, stderr) => {
        console.log(stdout);
    });
}

runCommand(process.argv[2]);

// vulnerable_eval.js
const userInput = process.argv[2];

function executeInput(input) {
    eval(input);
}

executeInput(userInput);
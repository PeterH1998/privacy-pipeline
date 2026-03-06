const userInput = process.argv[2];

// Vulnerable: executing user input
eval(userInput);